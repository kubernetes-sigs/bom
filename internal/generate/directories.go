/*
Copyright 2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package generate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/dependencies"
	"github.com/carabiner-dev/unpack/filesystem"
	fsoptions "github.com/carabiner-dev/unpack/filesystem/options"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/sirupsen/logrus"
)

// addDirectories resolves the directory patterns and adds each match
// to the document as a top-level package: codebases recognized by
// unpack (a go.mod at the directory root, for example) contribute
// their dependency graph, and the directory tree is indexed into file
// nodes contained by the package.
func addDirectories(ctx context.Context, doc *sbom.Document, opts *Options) error {
	for _, pattern := range opts.Directories {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return fmt.Errorf("globbing %q: %w", pattern, err)
		}
		if len(matches) == 0 {
			logrus.Warnf("no directories matched pattern %q", pattern)
			continue
		}
		for _, path := range matches {
			info, err := os.Stat(path)
			if err != nil {
				return fmt.Errorf("checking %q: %w", path, err)
			}
			if !info.IsDir() {
				continue
			}
			nl, err := directoryNodeList(ctx, path, opts)
			if err != nil {
				return fmt.Errorf("scanning directory %q: %w", path, err)
			}
			doc.GetNodeList().Add(nl)
		}
	}
	return nil
}

// directoryNodeList scans one directory into a node list rooted at
// its package node.
func directoryNodeList(ctx context.Context, dir string, opts *Options) (*sbom.NodeList, error) {
	nl, err := codebaseNodeList(ctx, dir, opts)
	if err != nil {
		return nil, err
	}
	if nl == nil {
		// Not a recognized codebase: a plain package named after the
		// directory, as the legacy generator produced.
		abs, err := filepath.Abs(dir)
		if err != nil {
			return nil, fmt.Errorf("resolving %q: %w", dir, err)
		}
		base := filepath.Base(abs)
		nl = &sbom.NodeList{}
		nl.AddRootNode(&sbom.Node{
			Id:   elementID("Package", base),
			Type: sbom.Node_PACKAGE,
			Name: base,
		})
	}
	if len(nl.GetRootElements()) == 0 {
		return nil, fmt.Errorf("no root element after scanning %q", dir)
	}

	rootID := nl.GetRootElements()[0]
	prefix := rootID
	if root := nl.GetNodeByID(rootID); root != nil && root.GetName() != "" {
		prefix = root.GetName()
	}
	files, err := indexFiles(dir, prefix, opts)
	if err != nil {
		return nil, err
	}
	// The directory license concluded from the file scan lands on the
	// package node, as the legacy generator recorded it. Its declared
	// license stays unset: the legacy generator never asserted one.
	if tag := concludeLicenses(files); tag != "" {
		if root := nl.GetNodeByID(rootID); root != nil {
			root.LicenseConcluded = tag
		}
	}
	if err := nl.RelateNodeListAtID(files, rootID, sbom.Edge_contains); err != nil {
		return nil, fmt.Errorf("relating files to %q: %w", rootID, err)
	}
	return nl, nil
}

// codebaseNodeList extracts the dependency graphs of the codebases
// unpack recognizes at the root of dir. Codebases nested in
// subdirectories are ignored, matching the legacy generator, which
// only ever read the go.mod at the directory root. Returns nil when
// the directory holds no recognized codebase.
func codebaseNodeList(ctx context.Context, dir string, opts *Options) (*sbom.NodeList, error) {
	// The unpacker options must be mutated in place: replacing the
	// struct clears its (unexported) logger.
	unpacker := dependencies.NewUnpacker()
	unpacker.Options.Networking = networkLevel(opts)
	unpacker.Options.IndexFiles = false
	unpacker.Options.IgnorePatterns = append(unpacker.Options.IgnorePatterns, opts.IgnorePatterns...)

	codebases, err := unpacker.ListCodebases(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("discovering codebases: %w", err)
	}

	var merged *sbom.NodeList
	for _, codebase := range codebases {
		if codebase.Path != "." {
			continue
		}
		unpacker.Options.CodebaseFilter = codebase.ID
		nl, err := unpacker.ExtractCodebaseWithContext(ctx, dir)
		if err != nil {
			return nil, fmt.Errorf("extracting %s codebase: %w", codebase.Language, err)
		}
		if nl == nil {
			continue
		}
		stripGoDirhashes(nl)
		if merged == nil {
			merged = nl
		} else {
			merged.Add(nl)
		}
	}
	return merged, nil
}

// indexFiles hashes the directory tree into file nodes with the
// checksums the legacy generator recorded (SHA1, SHA256 and SHA512)
// and each file's classified license, identified with legacy-style
// IDs and sorted for deterministic output.
func indexFiles(dir, prefix string, opts *Options) (*sbom.NodeList, error) {
	fsd, err := filesystem.New(
		fsoptions.WithAlgorithms([]intoto.HashAlgorithm{
			intoto.AlgorithmSHA1, intoto.AlgorithmSHA256, intoto.AlgorithmSHA512,
		}),
		fsoptions.WithIgnorePatterns(opts.IgnorePatterns),
		fsoptions.WithFileProcessor(licenseProcessorID),
	)
	if err != nil {
		return nil, fmt.Errorf("creating filesystem indexer: %w", err)
	}
	nl, err := fsd.IndexFS(os.DirFS(dir))
	if err != nil {
		return nil, fmt.Errorf("indexing files in %q: %w", dir, err)
	}

	nodes := nl.GetNodes()
	slices.SortFunc(nodes, func(a, b *sbom.Node) int {
		return strings.Compare(a.GetName(), b.GetName())
	})
	roots := make([]string, 0, len(nodes))
	for _, node := range nodes {
		node.Id = elementID("File", prefix+"-"+node.GetName())
		roots = append(roots, node.GetId())
	}
	nl.RootElements = roots
	return nl, nil
}

// stripGoDirhashes removes the SHA256 entries the golang decomposer
// stores on its dependency nodes. They hold the go.sum module hash,
// which is a hash over the module file tree (dirhash), not a digest
// of any artifact: rendered as an SPDX checksum it would never
// verify.
func stripGoDirhashes(nl *sbom.NodeList) {
	for _, node := range nl.GetNodes() {
		if node.GetType() != sbom.Node_PACKAGE {
			continue
		}
		if strings.HasPrefix(string(node.Purl()), "pkg:golang/") {
			delete(node.GetHashes(), int32(sbom.HashAlgorithm_SHA256))
		}
	}
}

// networkLevel maps the engine options to unpack's network policy.
func networkLevel(opts *Options) api.NetworkLevel {
	if opts.Offline {
		return api.NetworkDisabled
	}
	return api.NetworkEssential
}

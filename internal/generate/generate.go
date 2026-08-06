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

// Package generate implements bom's protobom-native SBOM generation
// engine. It maps bom's generation options onto unpack subjects and
// assembles the resulting node lists into a protobom document; the
// legacy DocBuilder API converts the result with pkg/spdx's
// FromProtobom to keep returning the legacy model.
//
// The engine keeps the observable conventions of the legacy generator
// where they matter to consumers: the same default namespace shape,
// the same creator identity, the same checksum algorithms, and
// element identifiers built with the legacy sanitization rules so
// converted documents keep the familiar SPDXRef- identifiers.
package generate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	fsoptions "github.com/carabiner-dev/unpack/filesystem/options"
	"github.com/carabiner-dev/unpack/filesystem/processors"
	"github.com/google/uuid"
	intoto "github.com/in-toto/attestation/go/v1"
	protospdx "github.com/protobom/protobom/pkg/formats/spdx"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	"sigs.k8s.io/release-utils/version"
)

// Options steers a generation run. The zero value produces an empty
// document with default metadata.
type Options struct {
	// Name is the document name. Left empty, downstream serializers
	// generate one, as the legacy renderer always did.
	Name string

	// Namespace is the document namespace URI. Left empty, the engine
	// generates the same UUID-based default namespace the legacy
	// generator used.
	Namespace string

	// CreatorPerson identifies the document author, in the SPDX actor
	// form "Name (email)".
	CreatorPerson string

	// Files lists paths, or glob patterns, of plain files to add to
	// the document as top-level elements.
	Files []string

	// Directories lists paths, or glob patterns, of source
	// directories to scan into top-level packages.
	Directories []string

	// Images lists OCI references of container images to scan into
	// top-level packages: the package inventory is read from the
	// image's squashed filesystem, and each layer is recorded as a
	// node carrying its digest. Multi-arch references expand into one
	// node per platform image under the index node.
	Images []string

	// ImageArchives lists paths, or glob patterns, of docker-archive
	// tarballs (the docker save format) to scan like Images.
	ImageArchives []string

	// Archives lists paths, or glob patterns, of tar archives,
	// compressed or not, to extract and scan into top-level packages
	// with the directory semantics.
	Archives []string

	// IgnorePatterns holds extra gitignore-syntax patterns applied
	// when scanning directories, in addition to the directory's own
	// .gitignore.
	IgnorePatterns []string

	// Offline disables all network access during decomposition. The
	// dependency data that needs the network (transitive Go module
	// graphs, license lookups) degrades to what the local sources
	// declare.
	Offline bool
}

// Document runs the engine and returns the generated protobom
// document.
func Document(ctx context.Context, opts *Options) (*sbom.Document, error) {
	if opts == nil {
		opts = &Options{}
	}
	doc := newDocument(opts)
	if err := addDirectories(ctx, doc, opts); err != nil {
		return nil, err
	}
	if err := addImages(ctx, doc, opts); err != nil {
		return nil, err
	}
	if err := addImageArchives(ctx, doc, opts); err != nil {
		return nil, err
	}
	if err := addArchives(ctx, doc, opts); err != nil {
		return nil, err
	}
	if err := addFiles(doc, opts.Files); err != nil {
		return nil, err
	}
	return doc, nil
}

// newDocument assembles the document and its metadata from the
// options.
func newDocument(opts *Options) *sbom.Document {
	doc := sbom.NewDocument()
	md := doc.GetMetadata()
	md.Name = opts.Name
	namespace := opts.Namespace
	if namespace == "" {
		namespace = "https://spdx.org/spdxdocs/k8s-releng-bom-" + uuid.NewString()
	}
	md.Id = namespace
	md.Date = timestamppb.Now()
	if opts.CreatorPerson != "" {
		_, name, email := protospdx.ParseActorString(opts.CreatorPerson)
		md.Authors = []*sbom.Person{{Name: name, Email: email}}
	}
	md.Tools = []*sbom.Tool{{Name: "bom", Version: version.GetVersionInfo().GitVersion}}
	return doc
}

// addFiles resolves the file patterns and adds each match to the
// document as a top-level file node. Patterns that match nothing are
// skipped with a warning and directories are ignored, the same
// treatment the legacy generator gave them.
func addFiles(doc *sbom.Document, patterns []string) error {
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return fmt.Errorf("globbing %q: %w", pattern, err)
		}
		if len(matches) == 0 {
			logrus.Warnf("no files matched pattern %q", pattern)
			continue
		}
		for _, path := range matches {
			info, err := os.Stat(path)
			if err != nil {
				return fmt.Errorf("checking %q: %w", path, err)
			}
			if info.IsDir() {
				continue
			}
			node, err := fileNode(path)
			if err != nil {
				return err
			}
			doc.GetNodeList().AddRootNode(node)
		}
	}
	return nil
}

// fileNode builds a file node carrying the checksums bom has always
// recorded for plain files, computed with unpack's file hasher.
func fileNode(path string) (*sbom.Node, error) {
	name := strings.TrimPrefix(path, "/")
	node := &sbom.Node{
		Id:       elementID("File", name),
		Type:     sbom.Node_FILE,
		Name:     name,
		FileName: name,
	}
	if err := hashFileInto(node, path); err != nil {
		return nil, err
	}
	return node, nil
}

// hashFileInto records the checksums bom has always recorded for
// artifacts (SHA1, SHA256 and SHA512) on the node, computed with
// unpack's file hasher.
func hashFileInto(node *sbom.Node, path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolving %q: %w", path, err)
	}
	hashOpts := &fsoptions.Options{
		Algorithms: []intoto.HashAlgorithm{
			intoto.AlgorithmSHA1, intoto.AlgorithmSHA256, intoto.AlgorithmSHA512,
		},
	}
	// The hasher opens FileName relative to the filesystem it is
	// handed; the display value is restored afterwards.
	saved := node.GetFileName()
	node.FileName = filepath.Base(abs)
	err = processors.NewHasher().Process(hashOpts, os.DirFS(filepath.Dir(abs)), node)
	node.FileName = saved
	if err != nil {
		return fmt.Errorf("hashing %q: %w", path, err)
	}
	return nil
}

// elementID builds a node identifier following the legacy SPDX ID
// sanitization rules, minus the SPDXRef- prefix that the converter to
// the legacy model adds back: path separators and colons become
// dashes, and any other character outside [a-zA-Z0-9.-] is replaced
// by its code point prefixed with C.
func elementID(kind, seed string) string {
	seed = strings.ReplaceAll(seed, "/", "-")
	seed = strings.ReplaceAll(seed, ":", "-")
	var sanitized strings.Builder
	for _, r := range seed {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
			sanitized.WriteRune(r)
		default:
			sanitized.WriteString("C")
			sanitized.WriteString(strconv.Itoa(int(r)))
		}
	}
	return kind + "-" + sanitized.String()
}

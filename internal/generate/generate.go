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
	"crypto/sha1" //nolint:gosec // SPDX file checksum, not a security use
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
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
	// the document as top-level elements. Go binaries among them
	// contain packages for the modules they were built from.
	Files []string

	// Directories lists paths, or glob patterns, of source
	// directories to scan into top-level packages.
	Directories []string

	// Images lists OCI references of container images to scan into
	// top-level packages: the package inventory (OS packages and Go
	// binaries) is read from the image's squashed filesystem, and each
	// layer is recorded as a node carrying its digest. Multi-arch
	// references expand into one node per platform image under the
	// index node.
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

	// NoGitignore stops the directory scan from reading the .gitignore
	// files it finds. Patterns in IgnorePatterns still apply.
	NoGitignore bool

	// OnlyDirectDeps keeps just the dependencies a codebase declares
	// itself, dropping the rest of the resolved dependency graph.
	OnlyDirectDeps bool

	// NoDependencies skips the dependency extraction of the codebases
	// found in directories and archives: their packages list only the
	// files they hold.
	NoDependencies bool

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
	encodePurls(doc.GetNodeList())
	return doc, nil
}

// addSourceNodeList adds the node list of one scanned source to the
// document. Sources are identified by their names, so two sources can
// claim the same identifiers (two directories named alike, say): the
// root of the later source, and the files indexed under it, are then
// renamed with the first free numeric suffix, as the legacy generator
// did, instead of merging into the earlier ones. Files collide even
// when the roots do not, like those of two codebases sharing a name but
// not a version. Other shared nodes, such as a dependency both sources
// use, still merge.
func addSourceNodeList(doc *sbom.Document, nl *sbom.NodeList) {
	existing := map[string]struct{}{}
	for _, node := range doc.GetNodeList().GetNodes() {
		existing[node.GetId()] = struct{}{}
	}
	roots := map[string]struct{}{}
	for _, id := range nl.GetRootElements() {
		roots[id] = struct{}{}
	}

	incoming := map[string]struct{}{}
	var ids []string
	for _, node := range nl.GetNodes() {
		incoming[node.GetId()] = struct{}{}
		_, isRoot := roots[node.GetId()]
		if _, ok := existing[node.GetId()]; ok && (isRoot || node.GetType() == sbom.Node_FILE) {
			ids = append(ids, node.GetId())
		}
	}
	if len(ids) == 0 {
		doc.GetNodeList().Add(nl)
		return
	}

	// A suffixed identifier must be free in the document and in the
	// source itself, which may hold files named like one (x-0001).
	for i := 1; ; i++ {
		suffix := fmt.Sprintf("-%04d", i)
		free := true
		for _, id := range ids {
			_, inDoc := existing[id+suffix]
			_, inSource := incoming[id+suffix]
			if inDoc || inSource {
				free = false
				break
			}
		}
		if !free {
			continue
		}
		renames := make(map[string]string, len(ids))
		for _, id := range ids {
			renames[id] = id + suffix
		}
		logrus.Infof(
			"Renaming %d elements of source %v with suffix %s to keep their identifiers unique",
			len(renames), nl.GetRootElements(), suffix,
		)
		logrus.Debugf("Renamed elements: %v", renames)
		renameNodes(nl, renames)
		break
	}
	doc.GetNodeList().Add(nl)
}

// encodePurls percent-encodes the plus signs some decomposers leave
// verbatim in purls (in Go pseudo versions and build metadata, for
// example). The purl specification reserves the character, so it has
// to be written %2B everywhere past the package type.
func encodePurls(nl *sbom.NodeList) {
	for _, node := range nl.GetNodes() {
		id := int32(sbom.SoftwareIdentifierType_PURL)
		p, ok := node.GetIdentifiers()[id]
		if !ok {
			continue
		}
		typ, rest, ok := strings.Cut(p, "/")
		if !ok || !strings.Contains(rest, "+") {
			continue
		}
		node.Identifiers[id] = typ + "/" + strings.ReplaceAll(rest, "+", "%2B")
	}
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
	md.Date = timestamppb.New(creationTime())
	if opts.CreatorPerson != "" {
		_, name, email := protospdx.ParseActorString(opts.CreatorPerson)
		md.Authors = []*sbom.Person{{Name: name, Email: email}}
	}
	md.Tools = []*sbom.Tool{{Name: "bom", Version: version.GetVersionInfo().GitVersion}}
	return doc
}

// creationTime returns the document creation time: the time set in
// SOURCE_DATE_EPOCH when it holds a valid Unix timestamp, so builds can
// produce reproducible documents, and the current time otherwise.
func creationTime() time.Time {
	if epoch := os.Getenv("SOURCE_DATE_EPOCH"); epoch != "" {
		secs, err := strconv.ParseInt(epoch, 10, 64)
		if err == nil && secs < 0 {
			err = errors.New("negative timestamp")
		}
		if err == nil {
			t := time.Unix(secs, 0).UTC()
			if err = timestamppb.New(t).CheckValid(); err == nil {
				return t
			}
		}
		logrus.Warnf("Ignoring invalid SOURCE_DATE_EPOCH %q: %v", epoch, err)
	}
	return time.Now()
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

			// Go binaries contain the modules they were built from.
			bin, err := goBinaryNodeList(path, node.GetFileName())
			if err != nil {
				return err
			}
			if bin == nil {
				continue
			}
			if err := doc.GetNodeList().RelateNodeListAtID(bin, node.GetId(), sbom.Edge_contains); err != nil {
				return fmt.Errorf("relating go modules to %q: %w", path, err)
			}
		}
	}
	return nil
}

// fileNode builds a file node carrying the checksums bom has always
// recorded for plain files.
func fileNode(path string) (*sbom.Node, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolving %q: %w", path, err)
	}
	name := strings.TrimPrefix(path, "/")
	node := &sbom.Node{
		Id:        elementID("File", name),
		Type:      sbom.Node_FILE,
		Name:      name,
		FileName:  name,
		FileTypes: fileTypes(os.DirFS(filepath.Dir(abs)), filepath.Base(abs)),
	}
	if err := hashFileInto(node, path); err != nil {
		return nil, err
	}
	return node, nil
}

// hashFileInto records the checksums bom has always recorded for
// artifacts (SHA1, SHA256 and SHA512) on the node.
func hashFileInto(node *sbom.Node, path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolving %q: %w", path, err)
	}
	hashes, err := hashFSFile(os.DirFS(filepath.Dir(abs)), filepath.Base(abs))
	if err != nil {
		return fmt.Errorf("hashing %q: %w", path, err)
	}
	node.Hashes = hashes
	return nil
}

// hashFSFile returns the artifact checksums (SHA1, SHA256 and SHA512)
// of a file of fsys, computed in a single sequential read. Unlike
// unpack's hasher (carabiner-dev/hasher v0.2.4), which blocks forever
// when a read fails, it returns read errors.
func hashFSFile(fsys fs.FS, name string) (map[int32]string, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sums := map[sbom.HashAlgorithm]hash.Hash{
		sbom.HashAlgorithm_SHA1:   sha1.New(), //nolint:gosec // SPDX file checksum, not a security use
		sbom.HashAlgorithm_SHA256: sha256.New(),
		sbom.HashAlgorithm_SHA512: sha512.New(),
	}
	writers := make([]io.Writer, 0, len(sums))
	for _, h := range sums {
		writers = append(writers, h)
	}
	if _, err := io.Copy(io.MultiWriter(writers...), f); err != nil {
		return nil, fmt.Errorf("reading %q: %w", name, err)
	}
	hashes := make(map[int32]string, len(sums))
	for algo, h := range sums {
		hashes[int32(algo)] = hex.EncodeToString(h.Sum(nil))
	}
	return hashes, nil
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

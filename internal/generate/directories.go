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
	goversion "go/version"
	"maps"
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
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
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
			addSourceNodeList(doc, nl)
		}
	}
	return nil
}

// directoryNodeList scans one directory into a node list rooted at
// its package node.
func directoryNodeList(ctx context.Context, dir string, opts *Options) (*sbom.NodeList, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolving %q: %w", dir, err)
	}
	return treeNodeList(ctx, dir, filepath.Base(abs), opts)
}

// treeNodeList scans a directory tree into a node list rooted at its
// package node. Trees holding no recognized codebase root a plain
// package named fallbackName, as the legacy generator produced.
func treeNodeList(ctx context.Context, dir, fallbackName string, opts *Options) (*sbom.NodeList, error) {
	var nl *sbom.NodeList
	if !opts.NoDependencies {
		var err error
		if nl, err = codebaseNodeList(ctx, dir, opts); err != nil {
			return nil, err
		}
	}
	if nl == nil {
		nl = &sbom.NodeList{}
		nl.AddRootNode(&sbom.Node{
			Id:   elementID("Package", fallbackName),
			Type: sbom.Node_PACKAGE,
			Name: fallbackName,
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
	// unpack matches the .gitignore patterns against the whole walked path
	// rather than the path below dir, so a pattern matching one of the
	// parent directories hides the codebases (an unpack bug).
	unpacker.Options.UseGitIgnore = !opts.NoGitignore

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
		selectGoModuleVersions(nl, readGoModuleVersions(dir))
		stripPackageNameFileNames(nl)
		assignCodebaseIDs(nl)
		if merged == nil {
			merged = nl
		} else {
			merged.Add(nl)
		}
	}
	if merged != nil && opts.OnlyDirectDeps {
		keepDirectDependencies(merged)
	}
	return merged, nil
}

// keepDirectDependencies drops every node the codebases do not reach in
// a single step. unpack resolves the whole dependency graph, while the
// legacy generator could be asked for just what a codebase declares
// itself; this trims the former to the latter.
func keepDirectDependencies(nl *sbom.NodeList) {
	// Expansion is measured from the roots as they were, so a direct
	// dependency does not go on to pull in its own.
	roots := map[string]struct{}{}
	for _, id := range nl.GetRootElements() {
		roots[id] = struct{}{}
	}

	keep := map[string]struct{}{}
	for id := range roots {
		keep[id] = struct{}{}
	}
	for _, edge := range nl.GetEdges() {
		if _, ok := roots[edge.GetFrom()]; !ok {
			continue
		}
		for _, to := range edge.GetTo() {
			keep[to] = struct{}{}
		}
	}

	var remove []string
	for _, node := range nl.GetNodes() {
		if _, ok := keep[node.GetId()]; !ok {
			remove = append(remove, node.GetId())
		}
	}
	nl.RemoveNodes(remove)
}

// goModuleVersions holds what the main module's go.mod and go.sum
// tell about version selection.
type goModuleVersions struct {
	// pruned reports whether the main module has a pruned module
	// graph (go 1.17 or later), in which its go.mod requires every
	// module providing a package to its build at the selected version.
	pruned bool

	// sum maps each module path to the highest version go.sum lists
	// for it, leaving out versions go.mod excludes. Without module
	// graph pruning, go.sum lists the go.mod of every module version in
	// the graph, so this is the version minimal version selection
	// picks.
	sum map[string]string
}

// selectGoModuleVersions trims the Go dependency graph unpack builds
// to the module versions the go command selects. unpack links every
// requirement of a module path to one version out of those go.sum
// lists, picked arbitrarily, so the graph names versions the build
// never uses, and which ones changes from run to run.
//
// With a pruned module graph, the main module's requirements are the
// build list and every other module is dropped. Otherwise each module
// path keeps the version go.sum selects, falling back to its highest
// version in the graph for paths go.sum does not list.
//
// Requirements on a dropped version move to the version kept for its
// module path, while the dropped version's own requirements, read from
// its go.mod, go away with it.
func selectGoModuleVersions(nl *sbom.NodeList, versions goModuleVersions) {
	roots := map[string]struct{}{}
	for _, id := range nl.GetRootElements() {
		roots[id] = struct{}{}
	}

	// The main module always wins selection, so a root claims its
	// module path whatever version it carries.
	modules := map[string]*sbom.Node{}
	selected := map[string]*sbom.Node{}
	for _, node := range nl.GetNodes() {
		if node.GetType() != sbom.Node_PACKAGE || !strings.HasPrefix(string(node.Purl()), "pkg:golang/") {
			continue
		}
		modules[node.GetId()] = node
		if _, ok := roots[node.GetId()]; ok {
			selected[node.GetName()] = node
		}
	}

	pickGoModuleVersions(nl, roots, modules, selected, versions)

	var remove []string
	renames := map[string]string{}
	for id, node := range modules {
		keep, ok := selected[node.GetName()]
		if keep == node {
			continue
		}
		remove = append(remove, id)
		if ok {
			renames[id] = keep.GetId()
		}
	}
	if len(remove) == 0 {
		return
	}

	for _, edge := range nl.GetEdges() {
		to := edge.GetTo()[:0]
		for _, id := range edge.GetTo() {
			if newID, ok := renames[id]; ok {
				id = newID
			}
			// An older version requiring a newer one of the same
			// module would otherwise leave the module depending on
			// itself.
			if id != edge.GetFrom() {
				to = append(to, id)
			}
		}
		edge.To = to
	}

	// Removing the nodes also drops the edges from and to them and
	// merges the duplicate targets the rewiring left behind.
	nl.RemoveNodes(remove)
}

// pickGoModuleVersions fills selected, keyed by module path and
// seeded with the main module, with the node kept for each module
// path, as selectGoModuleVersions describes.
func pickGoModuleVersions(
	nl *sbom.NodeList, roots map[string]struct{}, modules, selected map[string]*sbom.Node, versions goModuleVersions,
) {
	candidates := slices.Collect(maps.Values(modules))
	if versions.pruned {
		candidates = nil
		for _, edge := range nl.GetEdges() {
			if _, ok := roots[edge.GetFrom()]; !ok {
				continue
			}
			for _, id := range edge.GetTo() {
				if node, ok := modules[id]; ok {
					candidates = append(candidates, node)
				}
			}
		}
	}
	for _, node := range candidates {
		current, ok := selected[node.GetName()]
		if !ok {
			selected[node.GetName()] = node
			continue
		}
		if _, isRoot := roots[current.GetId()]; isRoot {
			continue
		}
		if sumVersion, ok := versions.sum[node.GetName()]; ok && !versions.pruned {
			// The node carrying the version go.sum selects wins
			// outright.
			if current.GetVersion() == sumVersion {
				continue
			}
			if node.GetVersion() == sumVersion {
				selected[node.GetName()] = node
				continue
			}
		}
		if newerModuleVersion(node.GetVersion(), current.GetVersion()) {
			selected[node.GetName()] = node
		}
	}

	// unpack only creates nodes for the versions requirements point
	// at, so the version go.sum selects may have none. The node kept
	// for the path then stands for it.
	if !versions.pruned {
		for path, node := range selected {
			if _, isRoot := roots[node.GetId()]; isRoot {
				continue
			}
			if v, ok := versions.sum[path]; ok && newerModuleVersion(v, node.GetVersion()) {
				node.Version = v
				node.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)] = "pkg:golang/" + path + "@" + v
			}
		}
	}
}

// readGoModuleVersions reads the version selection data from the
// go.mod and go.sum in dir. Missing or unreadable files leave the
// corresponding fields empty.
func readGoModuleVersions(dir string) goModuleVersions {
	var versions goModuleVersions
	data, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		return versions
	}
	excluded := map[string]struct{}{}
	file, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		// ParseLax skips exclude directives, but still reads the go
		// version from files Parse rejects.
		file, err = modfile.ParseLax("go.mod", data, nil)
		if err != nil {
			return versions
		}
	}
	if file.Go != nil {
		versions.pruned = goversion.Compare("go"+file.Go.Version, "go1.17") >= 0
	}
	for _, exclude := range file.Exclude {
		excluded[exclude.Mod.String()] = struct{}{}
	}
	if versions.pruned {
		return versions
	}

	sum, err := os.ReadFile(filepath.Join(dir, "go.sum"))
	if err != nil {
		return versions
	}
	versions.sum = map[string]string{}
	for line := range strings.Lines(string(sum)) {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		path, version := fields[0], strings.TrimSuffix(fields[1], "/go.mod")
		if !semver.IsValid(version) {
			continue
		}
		if _, ok := excluded[path+"@"+version]; ok {
			continue
		}
		if current, ok := versions.sum[path]; !ok || newerModuleVersion(version, current) {
			versions.sum[path] = version
		}
	}
	return versions
}

// newerModuleVersion reports whether module version a sorts above b
// in semantic version order, which pseudo-versions and +incompatible
// versions follow. Equal versions fall back to a string comparison to
// keep the pick deterministic.
func newerModuleVersion(a, b string) bool {
	if c := semver.Compare(a, b); c != 0 {
		return c > 0
	}
	return a > b
}

// assignCodebaseIDs replaces the random identifiers unpack assigns to
// codebase package nodes with deterministic legacy-style element ids
// seeded on the package name and version.
func assignCodebaseIDs(nl *sbom.NodeList) {
	renames := map[string]string{}
	for _, node := range nl.GetNodes() {
		if node.GetType() != sbom.Node_PACKAGE {
			continue
		}
		seed := node.GetName()
		if version := node.GetVersion(); version != "" {
			seed += "-" + version
		}
		renames[node.GetId()] = elementID("Package", seed)
	}
	renameNodes(nl, renames)
}

// indexFiles hashes the directory tree into file nodes with the
// checksums the legacy generator recorded (SHA1, SHA256 and SHA512)
// and each file's classified license, identified with legacy-style
// IDs and sorted for deterministic output.
func indexFiles(dir, prefix string, opts *Options) (*sbom.NodeList, error) {
	fsopts := []fsoptions.Function{
		fsoptions.WithAlgorithms([]intoto.HashAlgorithm{
			intoto.AlgorithmSHA1, intoto.AlgorithmSHA256, intoto.AlgorithmSHA512,
		}),
		fsoptions.WithIgnorePatterns(opts.IgnorePatterns),
		fsoptions.WithFileProcessor(licenseProcessorID),
	}
	if opts.NoGitignore {
		fsopts = append(fsopts, fsoptions.WithNoGitIgnore())
	}
	fsd, err := filesystem.New(fsopts...)
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
		node.FileTypes = fileTypes(os.DirFS(dir), node.GetName())
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

// stripPackageNameFileNames clears the file names unpack's npm and
// Cargo decomposers copy from the package name onto their package
// nodes. They name no file, so rendered as the SPDX package file name
// they would mislead.
func stripPackageNameFileNames(nl *sbom.NodeList) {
	for _, node := range nl.GetNodes() {
		if node.GetType() == sbom.Node_PACKAGE && node.GetFileName() == node.GetName() {
			node.FileName = ""
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

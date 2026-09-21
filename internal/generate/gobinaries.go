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
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"runtime/debug"
	"strings"
	"sync"

	api "github.com/carabiner-dev/unpack/api/v1"
	"github.com/carabiner-dev/unpack/system"
	purl "github.com/package-url/packageurl-go"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/sirupsen/logrus"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// registerGoBinaryDecomposer makes image scans report the Go binaries
// they find next to the OS packages. unpack's image unpacker reaches
// the system decomposers only through its process-wide unpacker
// registry and offers no way to add a decomposer per scan, so the
// system unpacker is registered again with the Go binary decomposer
// added. This happens on the first image scan rather than at init, so
// programs importing bom without scanning images keep unpack's
// defaults. Programs that do scan images through bom get the Go binary
// decomposer in their own system unpacker scans afterwards as well.
var registerGoBinaryDecomposer = sync.OnceFunc(func() {
	api.RegisterUnpacker(system.SubjectType, func() api.Unpacker {
		u := system.NewUnpacker()
		u.RegisterDecomposer(&goBinaryDecomposer{})
		return u
	})
})

var _ system.SystemDecomposer = (*goBinaryDecomposer)(nil)

// goBinaryDecomposer is a system decomposer reading the build
// information the Go linker embeds in every binary (what go version -m
// prints) from the regular files of a filesystem.
type goBinaryDecomposer struct{}

// DefaultOptions returns nil: the decomposer has no options.
func (d *goBinaryDecomposer) DefaultOptions() any { return nil }

// Requirements returns nothing: debug/buildinfo is pure Go.
func (d *goBinaryDecomposer) Requirements(*api.DecomposerOptions) []api.Requirement { return nil }

// Extract scans opts.WorkDir as the system root.
func (d *goBinaryDecomposer) Extract(opts *api.DecomposerOptions) (*sbom.NodeList, error) {
	if opts == nil || opts.WorkDir == "" {
		return nil, errors.New("go binary decomposer needs a WorkDir to use as the system root")
	}
	return d.ExtractFromFS(os.DirFS(opts.WorkDir), opts)
}

// ExtractFromFS walks the filesystem and returns a node list rooted at
// one package per Go binary found: its main module, carrying the
// binary's path and checksums. Returns (nil, nil) when there is none.
// Entries bom fails to read are skipped with a warning: a file bom
// cannot read is not a reason to fail the whole scan.
func (d *goBinaryDecomposer) ExtractFromFS(source fs.FS, _ *api.DecomposerOptions) (*sbom.NodeList, error) {
	nl := sbom.NewNodeList()
	modules := map[string]*sbom.Node{}
	err := fs.WalkDir(source, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			logrus.Warnf("skipping %q while looking for go binaries: %v", name, err)
			if entry != nil && entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		bin, err := readGoBinary(source, name)
		if err != nil {
			logrus.Warnf("skipping %q while looking for go binaries: %v", name, err)
			return nil
		}
		if bin == nil {
			return nil
		}
		hashes, err := hashFSFile(source, name)
		if err != nil {
			logrus.Warnf("skipping go binary %q: %v", name, err)
			return nil
		}
		main := addGoBinary(nl, modules, bin, "/"+name, hashes[int32(sbom.HashAlgorithm_SHA256)])
		main.Hashes = hashes
		nl.RootElements = append(nl.RootElements, main.GetId())
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking filesystem for go binaries: %w", err)
	}
	if len(nl.GetRootElements()) == 0 {
		return nil, nil
	}
	return nl, nil
}

// readGoBinary reads the Go build information of a file of the
// filesystem. Returns nil when the file is not a Go binary.
func readGoBinary(fsys fs.FS, name string) (*debug.BuildInfo, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	// Files of image filesystems are sequential only, so they are
	// wrapped to serve the random reads buildinfo needs.
	var closer io.Closer = f
	r, ok := f.(io.ReaderAt)
	if !ok {
		seq := &sequentialReaderAt{fsys: fsys, name: name, f: f}
		r, closer = seq, seq
	}
	defer closer.Close()
	return readBuildInfo(r)
}

// readBuildInfo returns the Go build information of an executable, nil
// when it is not a Go binary. buildinfo tells executables apart from
// their first bytes, so other files cost a single short read. It
// reports every failure as a format problem, so read errors are
// recorded on the way to tell them apart.
func readBuildInfo(r io.ReaderAt) (*debug.BuildInfo, error) {
	er := &errReaderAt{r: r}
	bin, err := buildinfo.Read(er)
	if er.err != nil {
		return nil, fmt.Errorf("reading go build information: %w", er.err)
	}
	if err != nil {
		return nil, nil //nolint:nilnil // not a Go binary
	}
	return bin, nil
}

// errReaderAt records the first error of the wrapped reader other than
// reaching the end of the file.
type errReaderAt struct {
	r   io.ReaderAt
	err error
}

func (e *errReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := e.r.ReadAt(p, off)
	if err != nil && e.err == nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		e.err = err
	}
	return n, err
}

// goBinaryNodeList reads the Go build information of the file at path
// into a node list rooted at the binary's main module package, which
// records fileName as its file name. Returns nil when the file is not
// a Go binary.
func goBinaryNodeList(filePath, fileName string) (*sbom.NodeList, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("opening %q: %w", filePath, err)
	}
	defer f.Close()
	bin, err := readBuildInfo(f)
	if err != nil {
		return nil, fmt.Errorf("reading %q: %w", filePath, err)
	}
	if bin == nil {
		return nil, nil
	}
	nl := sbom.NewNodeList()
	main := addGoBinary(nl, map[string]*sbom.Node{}, bin, fileName, "")
	nl.RootElements = append(nl.RootElements, main.GetId())
	return nl, nil
}

// addGoBinary adds the Go binary at binPath to the node list and
// returns the package of its main module, which records the path as
// its file name and depends on every module linked into the binary and
// on the Go standard library of the toolchain that built it. Module
// nodes are shared by the binaries of one node list through the
// modules map. The build information lists modules without their own
// dependency edges, so all of them hang off the main module.
//
// The SHA256 digest of the binary, when given, has a prefix of it become part of the
// identifier of the main module package, so the binaries found at the
// same path in the platform images of an index, or in different images,
// stay apart unless they are identical.
func addGoBinary(nl *sbom.NodeList, modules map[string]*sbom.Node, bin *debug.BuildInfo, binPath, digest string) *sbom.Node {
	main := goMainModuleNode(bin, binPath)
	// The main module package stands for the binary: its identifier
	// is seeded on the binary path, which tells apart binaries built
	// from the same module and the module used as a dependency.
	seed := strings.TrimPrefix(binPath, "/") + "-" + moduleSeed(main)
	if len(digest) >= 12 {
		seed += "-" + digest[:12]
	}
	main.Id = uniqueNodeID(nl, elementID("Package", seed))
	main.FileName = binPath
	main.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_APPLICATION}
	nl.AddNode(main)

	deps := make([]string, 0, len(bin.Deps)+1)
	for _, dep := range bin.Deps {
		deps = append(deps, sharedNode(nl, modules, goModuleNode(dep)).GetId())
	}
	if stdlib := goStdlibNode(bin.GoVersion); stdlib != nil {
		deps = append(deps, sharedNode(nl, modules, stdlib).GetId())
	}
	if len(deps) > 0 {
		nl.AddEdge(&sbom.Edge{Type: sbom.Edge_dependsOn, From: main.GetId(), To: deps})
	}
	return main
}

// sharedNode returns the node already recorded for an equal module,
// adding the node to the list when there is none yet. Modules are
// equal when their purls and comments match: the comment tells a
// replacement apart from the same module used directly, and local
// directory replacements, which have no version, apart from each
// other.
func sharedNode(nl *sbom.NodeList, modules map[string]*sbom.Node, node *sbom.Node) *sbom.Node {
	key := string(node.Purl()) + "\x00" + node.GetComment()
	if existing, ok := modules[key]; ok {
		return existing
	}
	node.Id = uniqueNodeID(nl, elementID("Package", moduleSeed(node)))
	modules[key] = node
	nl.AddNode(node)
	return node
}

// moduleSeed returns the element id seed of a module node: its name
// and version, plus a digest of its comment when it has one, which
// tells a replacement apart from the module used directly.
func moduleSeed(node *sbom.Node) string {
	seed := node.GetName()
	if node.GetVersion() != "" {
		seed += "-" + node.GetVersion()
	}
	if node.GetComment() != "" {
		sum := sha256.Sum256([]byte(node.GetComment()))
		seed += "-" + hex.EncodeToString(sum[:4])
	}
	return seed
}

// uniqueNodeID returns id, or id with the first free numeric suffix
// when the node list holds a node with that identifier already.
func uniqueNodeID(nl *sbom.NodeList, id string) string {
	if nl.GetNodeByID(id) == nil {
		return id
	}
	for i := 1; ; i++ {
		candidate := fmt.Sprintf("%s-%04d", id, i)
		if nl.GetNodeByID(candidate) == nil {
			return candidate
		}
	}
}

// goMainModuleNode builds the package node of a binary's main module.
// Binaries built from files rather than a module (go build main.go)
// have no main module: their package is named after the binary and has
// no purl. The main module version comes from version control, so it
// often names a commit no proxy serves: the package records no download
// location, and no version at all for builds of modified trees
// (+dirty), which match no commit.
func goMainModuleNode(bin *debug.BuildInfo, binPath string) *sbom.Node {
	if bin.Main.Path == "" {
		name := bin.Path
		if name == "" || name == "command-line-arguments" {
			name = path.Base(binPath)
		}
		return &sbom.Node{Type: sbom.Node_PACKAGE, Name: name}
	}
	mod := bin.Main
	if strings.HasSuffix(mod.Version, "+dirty") {
		mod.Version = ""
	}
	node := goModuleNode(&mod)
	node.UrlDownload = ""
	return node
}

// goModuleNode builds the package node of a module listed in the build
// information. Replaced modules are recorded as their replacement,
// which is what the binary was built from, with the original noted in
// the comment. No checksum is recorded: the build information carries
// the go.sum module hash, which is not a digest of any artifact (see
// stripGoDirhashes).
func goModuleNode(mod *debug.Module) *sbom.Node {
	node := &sbom.Node{
		Type:           sbom.Node_PACKAGE,
		Name:           mod.Path,
		Version:        mod.Version,
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY},
	}
	if repl := mod.Replace; repl != nil {
		if modfile.IsDirectoryPath(repl.Path) {
			// A local directory replacement has no module identity of
			// its own; the module keeps its path, without a version.
			node.Version = ""
			node.Comment = "replaced by local directory " + repl.Path
		} else {
			node.Name = repl.Path
			node.Version = repl.Version
			node.Comment = "replaces " + mod.Path + "@" + mod.Version
		}
	}
	// Modules built from a working tree report (devel), which is not
	// a version a purl or the module proxy can resolve.
	version := ""
	if semver.IsValid(node.GetVersion()) {
		version = node.GetVersion()
		node.UrlDownload = goProxyURL(node.GetName(), version)
	}
	node.Identifiers = map[int32]string{int32(sbom.SoftwareIdentifierType_PURL): goPurl(node.GetName(), version)}
	return node
}

// goPurl builds the purl of a Go module, with the module path split
// into namespace and name as the purl specification defines for the
// golang type. version may be empty.
func goPurl(modulePath, version string) string {
	namespace, name := path.Split(modulePath)
	return purl.NewPackageURL(
		purl.TypeGolang, strings.TrimSuffix(namespace, "/"), name, version, nil, "",
	).ToString()
}

// goProxyURL returns the module zip URL of the public Go module proxy,
// with the module path and version escaped as the proxy protocol
// requires (upper case letters become '!' and their lower case form).
// Returns an empty string for paths or versions the proxy cannot
// serve.
func goProxyURL(modulePath, version string) string {
	escPath, err := module.EscapePath(modulePath)
	if err != nil {
		return ""
	}
	escVersion, err := module.EscapeVersion(version)
	if err != nil {
		return ""
	}
	return "https://proxy.golang.org/" + escPath + "/@v/" + escVersion + ".zip"
}

// goStdlibNode builds the node of the Go standard library linked into a
// binary, shaped like the one unpack's Go decomposer records for
// codebases. goVersion is the toolchain version the build information
// reports ("go1.26.1", possibly followed by build settings). Returns
// nil for toolchains without a release version.
func goStdlibNode(goVersion string) *sbom.Node {
	fields := strings.Fields(goVersion)
	if len(fields) == 0 || !strings.HasPrefix(fields[0], "go1") {
		return nil
	}
	version := strings.TrimPrefix(fields[0], "go")
	return &sbom.Node{
		Type:    sbom.Node_PACKAGE,
		Name:    "stdlib",
		Version: version,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): goPurl("stdlib", version),
		},
		Licenses:       []string{"BSD-3-Clause"},
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY},
	}
}

// sequentialReaderAt serves random reads from a file that can only be
// read front to back, as the files of unpack's squashed image
// filesystem are: reads past the current position skip ahead, and
// reads behind it reopen the file. buildinfo only needs a handful of
// reads, so this stays cheap without buffering the file in memory.
type sequentialReaderAt struct {
	fsys fs.FS
	name string
	f    fs.File
	pos  int64
}

func (r *sequentialReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < r.pos || r.f == nil {
		if err := r.Close(); err != nil {
			return 0, err
		}
		f, err := r.fsys.Open(r.name)
		if err != nil {
			return 0, err
		}
		r.f, r.pos = f, 0
	}
	if off > r.pos {
		n, err := io.CopyN(io.Discard, r.f, off-r.pos)
		r.pos += n
		if err != nil {
			return 0, err
		}
	}
	n, err := io.ReadFull(r.f, p)
	r.pos += int64(n)
	if errors.Is(err, io.ErrUnexpectedEOF) {
		err = io.EOF
	}
	return n, err
}

// Close releases the file the reader holds.
func (r *sequentialReaderAt) Close() error {
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}

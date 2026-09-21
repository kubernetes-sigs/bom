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
	"errors"
	"io"
	"io/fs"
	"math"
	"os"
	"runtime/debug"
	"testing"
	"testing/fstest"
	"time"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoModuleNode(t *testing.T) {
	for _, tc := range []struct {
		name         string
		mod          *debug.Module
		wantName     string
		wantVersion  string
		wantPurl     string
		wantComment  string
		wantDownload string
	}{
		{
			name:         "released module",
			mod:          &debug.Module{Path: "example.com/dep", Version: "v1.2.3"},
			wantName:     "example.com/dep",
			wantVersion:  "v1.2.3",
			wantPurl:     "pkg:golang/example.com/dep@v1.2.3",
			wantDownload: "https://proxy.golang.org/example.com/dep/@v/v1.2.3.zip",
		},
		{
			name:         "escaped path and version",
			mod:          &debug.Module{Path: "github.com/BurntSushi/toml", Version: "v2.0.0-RC1+incompatible"},
			wantName:     "github.com/BurntSushi/toml",
			wantVersion:  "v2.0.0-RC1+incompatible",
			wantPurl:     "pkg:golang/github.com/BurntSushi/toml@v2.0.0-RC1%2Bincompatible",
			wantDownload: "https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/v2.0.0-!r!c1+incompatible.zip",
		},
		{
			name:        "working tree build",
			mod:         &debug.Module{Path: "example.com/app", Version: "(devel)"},
			wantName:    "example.com/app",
			wantVersion: "(devel)",
			wantPurl:    "pkg:golang/example.com/app",
		},
		{
			name: "module replacement",
			mod: &debug.Module{
				Path: "example.com/dep", Version: "v1.2.3",
				Replace: &debug.Module{Path: "example.com/fork", Version: "v1.2.4"},
			},
			wantName:     "example.com/fork",
			wantVersion:  "v1.2.4",
			wantPurl:     "pkg:golang/example.com/fork@v1.2.4",
			wantComment:  "replaces example.com/dep@v1.2.3",
			wantDownload: "https://proxy.golang.org/example.com/fork/@v/v1.2.4.zip",
		},
		{
			name: "local replacement",
			mod: &debug.Module{
				Path: "example.com/dep", Version: "v1.2.3",
				Replace: &debug.Module{Path: "../dep", Version: "(devel)"},
			},
			wantName:    "example.com/dep",
			wantPurl:    "pkg:golang/example.com/dep",
			wantComment: "replaced by local directory ../dep",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := goModuleNode(tc.mod)
			require.Equal(t, tc.wantName, node.GetName())
			require.Equal(t, tc.wantVersion, node.GetVersion())
			require.Equal(t, tc.wantPurl, string(node.Purl()))
			require.Equal(t, tc.wantComment, node.GetComment())
			require.Equal(t, tc.wantDownload, node.GetUrlDownload())
			require.Empty(t, node.GetHashes(), "the go.sum hash is no artifact digest")
		})
	}
}

func TestGoMainModuleNode(t *testing.T) {
	for _, tc := range []struct {
		name        string
		bin         *debug.BuildInfo
		wantName    string
		wantVersion string
		wantPurl    string
	}{
		{
			name:     "no main module",
			bin:      &debug.BuildInfo{Path: "command-line-arguments"},
			wantName: "tool",
		},
		{
			name:     "no main module, gopath build",
			bin:      &debug.BuildInfo{Path: "example.com/cmd/tool"},
			wantName: "example.com/cmd/tool",
		},
		{
			name: "vcs version",
			bin: &debug.BuildInfo{Main: debug.Module{
				Path: "example.com/app", Version: "v0.0.0-20260917150225-20b26f51c76b",
			}},
			wantName:    "example.com/app",
			wantVersion: "v0.0.0-20260917150225-20b26f51c76b",
			wantPurl:    "pkg:golang/example.com/app@v0.0.0-20260917150225-20b26f51c76b",
		},
		{
			name: "modified tree",
			bin: &debug.BuildInfo{Main: debug.Module{
				Path: "example.com/app", Version: "v1.2.3+dirty",
			}},
			wantName: "example.com/app",
			wantPurl: "pkg:golang/example.com/app",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := goMainModuleNode(tc.bin, "/usr/bin/tool")
			require.Equal(t, tc.wantName, node.GetName())
			require.Equal(t, tc.wantVersion, node.GetVersion())
			require.Equal(t, tc.wantPurl, string(node.Purl()))
			require.Empty(t, node.GetUrlDownload(), "vcs versions are not served by the proxy")
		})
	}
}

func TestGoStdlibNode(t *testing.T) {
	node := goStdlibNode("go1.26.1 X:boringcrypto")
	require.NotNil(t, node)
	require.Equal(t, "stdlib", node.GetName())
	require.Equal(t, "1.26.1", node.GetVersion())
	require.Equal(t, "pkg:golang/stdlib@1.26.1", string(node.Purl()))

	require.Nil(t, goStdlibNode("devel go1.27-abcdef"))
	require.Nil(t, goStdlibNode(""))
}

func TestAddGoBinarySharesModules(t *testing.T) {
	dep := &debug.Module{Path: "example.com/dep", Version: "v1.0.0"}
	nl := sbom.NewNodeList()
	modules := map[string]*sbom.Node{}
	mains := map[string]struct{}{}
	for _, path := range []string{"/bin/a", "/bin/b"} {
		main := addGoBinary(nl, modules, &debug.BuildInfo{
			GoVersion: "go1.26.1",
			Main:      debug.Module{Path: "example.com/app", Version: "(devel)"},
			Deps:      []*debug.Module{dep},
		}, path, "")
		require.Equal(t, path, main.GetFileName())
		mains[main.GetId()] = struct{}{}
	}

	require.Len(t, mains, 2, "one package per binary")
	require.Len(t, nl.GetNodes(), 4, "two binaries sharing a module and the stdlib")
	ids := make([]string, 0, len(nl.GetNodes()))
	for _, node := range nl.GetNodes() {
		ids = append(ids, node.GetId())
	}
	require.ElementsMatch(t, []string{
		"Package-bin-a-example.com-app-C40develC41",
		"Package-bin-b-example.com-app-C40develC41",
		"Package-example.com-dep-v1.0.0",
		"Package-stdlib-1.26.1",
	}, ids, "identifiers derive from the binaries and modules")
	for id := range mains {
		edge := nl.GetEdgeByType(id, sbom.Edge_dependsOn)
		require.NotNil(t, edge)
		require.Len(t, edge.GetTo(), 2)
	}
}

// TestAddGoBinaryDigest checks that binaries at the same path built from
// the same module, as in the platform images of an index, keep apart
// when their contents differ and merge when they are identical.
func TestAddGoBinaryDigest(t *testing.T) {
	bin := &debug.BuildInfo{Main: debug.Module{Path: "example.com/app", Version: "v1.0.0"}}
	amd64 := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	arm64 := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

	doc := sbom.NewDocument()
	for _, digest := range []string{amd64, arm64, amd64} {
		// Each image scans into a node list of its own.
		nl := sbom.NewNodeList()
		main := addGoBinary(nl, map[string]*sbom.Node{}, bin, "/usr/bin/app", digest)
		nl.RootElements = append(nl.RootElements, main.GetId())
		doc.GetNodeList().Add(nl)
	}
	ids := make([]string, 0, len(doc.GetNodeList().GetNodes()))
	for _, node := range doc.GetNodeList().GetNodes() {
		ids = append(ids, node.GetId())
	}
	require.ElementsMatch(t, []string{
		"Package-usr-bin-app-example.com-app-v1.0.0-0123456789ab",
		"Package-usr-bin-app-example.com-app-v1.0.0-fedcba987654",
	}, ids)
}

func TestAddGoBinaryKeepsModuleVariantsApart(t *testing.T) {
	fork := &debug.Module{Path: "example.com/fork", Version: "v1.0.0"}
	nl := sbom.NewNodeList()
	modules := map[string]*sbom.Node{}
	for _, dep := range []*debug.Module{
		// The fork used directly and as a replacement.
		fork,
		{Path: "example.com/dep", Version: "v1.0.0", Replace: fork},
		// The same module replaced by different local directories.
		{Path: "example.com/lib", Version: "v1.0.0", Replace: &debug.Module{Path: "../lib"}},
		{Path: "example.com/lib", Version: "v1.0.0", Replace: &debug.Module{Path: "../other/lib"}},
		// Shared again.
		{Path: "example.com/lib", Version: "v1.0.0", Replace: &debug.Module{Path: "../lib"}},
	} {
		addGoBinary(nl, modules, &debug.BuildInfo{
			Main: debug.Module{Path: "example.com/app"},
			Deps: []*debug.Module{dep},
		}, "/bin/app", "")
	}

	comments := map[string][]string{}
	for _, node := range nl.GetNodes() {
		if node.GetName() != "example.com/app" {
			comments[node.GetName()] = append(comments[node.GetName()], node.GetComment())
		}
	}
	require.ElementsMatch(t, []string{"", "replaces example.com/dep@v1.0.0"}, comments["example.com/fork"])
	require.ElementsMatch(t, []string{
		"replaced by local directory ../lib", "replaced by local directory ../other/lib",
	}, comments["example.com/lib"])

	seen := map[string]struct{}{}
	for _, node := range nl.GetNodes() {
		_, dup := seen[node.GetId()]
		require.False(t, dup, "identifier %q is not unique", node.GetId())
		seen[node.GetId()] = struct{}{}
	}
}

// failingFS fails reading the files opened after the first failAfter
// opens.
type failingFS struct {
	fs.FS
	opens     int
	failAfter int
}

func (f *failingFS) Open(name string) (fs.File, error) {
	file, err := f.FS.Open(name)
	if err != nil {
		return nil, err
	}
	f.opens++
	if f.opens > f.failAfter {
		return failingFile{file}, nil
	}
	return file, nil
}

func (f *failingFS) ReadDir(name string) ([]fs.DirEntry, error) { return fs.ReadDir(f.FS, name) }

type failingFile struct{ fs.File }

func (failingFile) Read([]byte) (int, error) { return 0, errors.New("input/output error") }

func TestReadBuildInfoErrors(t *testing.T) {
	self, err := os.Executable()
	require.NoError(t, err)
	data, err := os.ReadFile(self)
	require.NoError(t, err)

	bin, err := readGoBinary(fstest.MapFS{"bin": {Data: data}}, "bin")
	require.NoError(t, err)
	require.NotNil(t, bin, "the test binary is a go binary")

	bin, err = readGoBinary(fstest.MapFS{"text": {Data: []byte("#!/bin/sh\necho not a binary\n")}}, "text")
	require.NoError(t, err, "other files are no error")
	require.Nil(t, bin)

	bin, err = readGoBinary(sequentialFS{&failingFS{FS: fstest.MapFS{"bin": {Data: data}}}}, "bin")
	require.ErrorContains(t, err, "input/output error", "read errors are reported")
	require.Nil(t, bin)
}

// TestExtractFromFSReadErrors fails the reads of the scan at every
// step, including the checksum read that follows the build information
// reads, which must not block.
func TestExtractFromFSReadErrors(t *testing.T) {
	self, err := os.Executable()
	require.NoError(t, err)
	data, err := os.ReadFile(self)
	require.NoError(t, err)
	files := fstest.MapFS{"usr/bin/app": {Data: data}}

	// Count the opens of a successful scan.
	counting := &failingFS{FS: files, failAfter: math.MaxInt}
	nl, err := (&goBinaryDecomposer{}).ExtractFromFS(sequentialFS{counting}, nil)
	require.NoError(t, err)
	require.Len(t, nl.GetRootElements(), 1)
	require.Greater(t, counting.opens, 1)

	for failAfter := range counting.opens {
		done := make(chan struct{})
		go func() {
			defer close(done)
			nl, err := (&goBinaryDecomposer{}).ExtractFromFS(
				sequentialFS{&failingFS{FS: files, failAfter: failAfter}}, nil,
			)
			assert.NoError(t, err)
			assert.Nil(t, nl, "the unreadable binary is skipped")
		}()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Fatalf("scan failing after %d opens did not return", failAfter)
		}
	}
}

func TestHashFSFileReadError(t *testing.T) {
	_, err := hashFSFile(&failingFS{FS: fstest.MapFS{"f": {Data: []byte("x")}}}, "f")
	require.ErrorContains(t, err, "input/output error")

	hashes, err := hashFSFile(fstest.MapFS{"f": {Data: []byte("x")}}, "f")
	require.NoError(t, err)
	require.Equal(t, map[int32]string{
		int32(sbom.HashAlgorithm_SHA1):   "11f6ad8ec52a2984abaafd7c3b516503785c2072",
		int32(sbom.HashAlgorithm_SHA256): "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
		int32(sbom.HashAlgorithm_SHA512): "a4abd4448c49562d828115d13a1fccea927f52b4d5459297f8b43e42da89238bc13626e43dcb38ddb082488927ec904fb42057443983e88585179d50551afe62",
	}, hashes)
}

// sequentialFS hides the io.ReaderAt implementation of its files, as
// unpack's image filesystem does.
type sequentialFS struct{ fs.FS }

func (s sequentialFS) Open(name string) (fs.File, error) {
	f, err := s.FS.Open(name)
	if err != nil {
		return nil, err
	}
	return sequentialFile{f}, nil
}

func (s sequentialFS) ReadDir(name string) ([]fs.DirEntry, error) { return fs.ReadDir(s.FS, name) }

type sequentialFile struct{ fs.File }

func TestSequentialReaderAt(t *testing.T) {
	fsys := sequentialFS{fstest.MapFS{"f": {Data: []byte("0123456789")}}}
	f, err := fsys.Open("f")
	require.NoError(t, err)
	_, ok := f.(io.ReaderAt)
	require.False(t, ok)

	r := &sequentialReaderAt{fsys: fsys, name: "f", f: f}
	t.Cleanup(func() { require.NoError(t, r.Close()) })
	buf := make([]byte, 3)
	for _, tc := range []struct {
		off  int64
		want string
	}{
		{4, "456"}, {0, "012"}, {7, "789"}, {1, "123"},
	} {
		n, err := r.ReadAt(buf, tc.off)
		require.NoError(t, err)
		require.Equal(t, tc.want, string(buf[:n]))
	}

	n, err := r.ReadAt(buf, 8)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, "89", string(buf[:n]))

	for _, off := range []int64{10, 11, 3} {
		n, err := r.ReadAt(buf, off)
		if off < 10 {
			require.NoError(t, err, "reading behind the end of the file reopens it")
			require.Equal(t, "345", string(buf[:n]))
			continue
		}
		require.ErrorIs(t, err, io.EOF, "offset %d", off)
		require.Zero(t, n)
	}
}

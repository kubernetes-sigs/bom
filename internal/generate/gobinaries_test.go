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

package generate_test

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/spdx/tools-golang/tagvalue"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/bom/internal/generate"
	"sigs.k8s.io/bom/pkg/serialize"
	"sigs.k8s.io/bom/pkg/spdx"
)

// buildGoBinary compiles a module depending on a locally replaced
// module, so the build needs no network, and returns the binary path.
func buildGoBinary(t *testing.T) string {
	t.Helper()
	return goBuild(t, map[string]string{
		"lib/go.mod":  "module example.com/lib\n\ngo 1.22\n",
		"lib/lib.go":  "package lib\n\nconst Name = \"lib\"\n",
		"app/go.mod":  "module example.com/app\n\ngo 1.22\n\nrequire example.com/lib v1.0.0\n\nreplace example.com/lib => ../lib\n",
		"app/main.go": "package main\n\nimport \"example.com/lib\"\n\nfunc main() { println(lib.Name) }\n",
	}, "app", ".")
}

// goBuild writes the files to a temporary directory, runs go build
// with the arguments in its subdirectory pkgDir and returns the path of
// the binary.
func goBuild(t *testing.T, files map[string]string, pkgDir string, args ...string) string {
	t.Helper()
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not found")
	}
	dir := t.TempDir()
	for file, content := range files {
		path := filepath.Join(dir, file)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
	bin := filepath.Join(dir, "app.bin")
	cmd := exec.CommandContext(t.Context(), gobin, append([]string{"build", "-o", bin}, args...)...)
	cmd.Dir = filepath.Join(dir, pkgDir)
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off", "GOFLAGS=", "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "building test binary: %s", out)
	return bin
}

// requireGoBinary checks the package recorded for the test binary and
// the modules it depends on.
func requireGoBinary(t *testing.T, nl *sbom.NodeList, pkg *sbom.Node, fileName string) {
	t.Helper()
	require.Equal(t, fileName, pkg.GetFileName())
	require.Equal(t, "example.com/app", pkg.GetName())
	require.Equal(t, "(devel)", pkg.GetVersion())
	require.Equal(t, "pkg:golang/example.com/app", string(pkg.Purl()))
	require.Equal(t, []sbom.Purpose{sbom.Purpose_APPLICATION}, pkg.GetPrimaryPurpose())

	edge := nl.GetEdgeByType(pkg.GetId(), sbom.Edge_dependsOn)
	require.NotNil(t, edge)
	purls := make([]string, 0, len(edge.GetTo()))
	for _, id := range edge.GetTo() {
		dep := nl.GetNodeByID(id)
		require.NotNil(t, dep)
		purls = append(purls, string(dep.Purl()))
	}
	// Merging node lists doesn't keep the order of the edge destinations.
	slices.Sort(purls)
	require.Len(t, purls, 2)
	require.Equal(t, "pkg:golang/example.com/lib", purls[0])
	require.True(t, strings.HasPrefix(purls[1], "pkg:golang/stdlib@1."), "stdlib purl %q", purls[1])
}

func TestFilesGoBinary(t *testing.T) {
	bin := buildGoBinary(t)
	text := filepath.Join(t.TempDir(), "notes.txt")
	require.NoError(t, os.WriteFile(text, []byte("not a binary"), 0o600))

	doc, err := generate.Document(t.Context(), &generate.Options{
		Files: []string{bin, text},
	})
	require.NoError(t, err)

	nl := doc.GetNodeList()
	require.Len(t, nl.GetRootElements(), 2)
	for _, id := range nl.GetRootElements() {
		file := nl.GetNodeByID(id)
		require.NotNil(t, file)
		if file.GetName() != strings.TrimPrefix(bin, "/") {
			require.Nil(t, nl.GetEdgeByType(id, sbom.Edge_contains), "plain files contain no packages")
			continue
		}
		contains := nl.GetEdgeByType(id, sbom.Edge_contains)
		require.NotNil(t, contains)
		require.Len(t, contains.GetTo(), 1)
		requireGoBinary(t, nl, nl.GetNodeByID(contains.GetTo()[0]), file.GetFileName())
	}
}

// TestFilesGoBinaryNoMainModule covers binaries built from files
// rather than a module, which record no main module.
func TestFilesGoBinaryNoMainModule(t *testing.T) {
	bin := goBuild(t, map[string]string{
		"src/main.go": "package main\n\nfunc main() { println(\"hello\") }\n",
	}, "src", "main.go")

	doc, err := generate.Document(t.Context(), &generate.Options{Files: []string{bin}})
	require.NoError(t, err)

	nl := doc.GetNodeList()
	require.Len(t, nl.GetRootElements(), 1)
	contains := nl.GetEdgeByType(nl.GetRootElements()[0], sbom.Edge_contains)
	require.NotNil(t, contains)
	require.Len(t, contains.GetTo(), 1)
	pkg := nl.GetNodeByID(contains.GetTo()[0])
	require.Equal(t, "app.bin", pkg.GetName(), "the package is named after the binary")
	require.Empty(t, pkg.GetVersion())
	require.Empty(t, pkg.Purl())
	require.Empty(t, pkg.GetUrlDownload())

	ldoc, err := spdx.FromProtobom(doc)
	require.NoError(t, err)
	tv, err := (&serialize.TagValue{}).Serialize(ldoc)
	require.NoError(t, err)
	parsed, err := tagvalue.Read(strings.NewReader(tv))
	require.NoError(t, err)
	names := make([]string, 0, len(parsed.Packages))
	for _, p := range parsed.Packages {
		names = append(names, p.PackageName)
	}
	require.ElementsMatch(t, []string{"app.bin", "stdlib"}, names)

	out, err := (&serialize.JSON{}).Serialize(ldoc)
	require.NoError(t, err)
	require.NotContains(t, out, `"name": ""`)
	require.NotContains(t, out, `"pkg:golang/"`)
}

// TestFilesGoBinaryTagValue reads the tag-value rendering of a Go
// binary listed between other files back with the SPDX tools: the
// files must stay on the document level, next to the module packages.
func TestFilesGoBinaryTagValue(t *testing.T) {
	bin := buildGoBinary(t)
	dir := filepath.Dir(bin)
	files := make([]string, 0, 2)
	for _, name := range []string{"a.txt", "z.txt"} {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(name), 0o600))
		files = append(files, path)
	}

	doc, err := generate.Document(t.Context(), &generate.Options{
		Namespace: "https://sbom.k8s.io/test/go-binary-tag-value",
		Files:     append(files, bin),
	})
	require.NoError(t, err)
	ldoc, err := spdx.FromProtobom(doc)
	require.NoError(t, err)

	var tv string
	for i := range 5 {
		out, err := (&serialize.TagValue{}).Serialize(ldoc)
		require.NoError(t, err)
		if i > 0 {
			require.Equal(t, tv, out, "the rendering is stable")
		}
		tv = out
	}

	parsed, err := tagvalue.Read(strings.NewReader(tv))
	require.NoError(t, err)
	fileNames := make([]string, 0, len(parsed.Files))
	for _, f := range parsed.Files {
		fileNames = append(fileNames, f.FileName)
	}
	require.ElementsMatch(t, []string{
		strings.TrimPrefix(files[0], "/"), strings.TrimPrefix(files[1], "/"), strings.TrimPrefix(bin, "/"),
	}, fileNames)
	names := make([]string, 0, len(parsed.Packages))
	for _, p := range parsed.Packages {
		require.Empty(t, p.Files, "package %s owns no files", p.PackageName)
		names = append(names, p.PackageName)
	}
	slices.Sort(names)
	require.Len(t, names, 3)
	require.Equal(t, []string{"example.com/app", "example.com/lib"}, names[:2])
	require.Equal(t, "stdlib", names[2])
}

func TestImageArchivesGoBinary(t *testing.T) {
	data, err := os.ReadFile(buildGoBinary(t))
	require.NoError(t, err)
	osRelease, err := os.ReadFile("../../test/golden/testdata/image/os-release")
	require.NoError(t, err)
	dpkgStatus, err := os.ReadFile("../../test/golden/testdata/image/dpkg-status")
	require.NoError(t, err)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, entry := range []struct {
		name    string
		mode    int64
		content []byte
	}{
		{"etc/os-release", 0o644, osRelease},
		{"var/lib/dpkg/status", 0o644, dpkgStatus},
		{"usr/bin/app", 0o755, data},
	} {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name: entry.name, Mode: entry.mode, Size: int64(len(entry.content)),
		}))
		_, err = tw.Write(entry.content)
		require.NoError(t, err)
	}
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: "app", Typeflag: tar.TypeSymlink, Linkname: "usr/bin/app",
	}))
	require.NoError(t, tw.Close())
	layerData := buf.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(layerData)), nil
	})
	require.NoError(t, err)
	img, err := mutate.AppendLayers(empty.Image, layer)
	require.NoError(t, err)

	tag, err := name.NewTag("registry.k8s.io/bom-go-test:v1.0.0")
	require.NoError(t, err)
	archive := filepath.Join(t.TempDir(), "image.tar")
	require.NoError(t, tarball.MultiWriteToFile(archive, map[name.Tag]v1.Image{tag: img}))

	doc, err := generate.Document(t.Context(), &generate.Options{
		ImageArchives: []string{archive},
	})
	require.NoError(t, err)

	nl := doc.GetNodeList()
	require.Len(t, nl.GetRootElements(), 1)
	_, packages := imageChildren(t, nl, nl.GetRootElements()[0])
	var app *sbom.Node
	names := make([]string, 0, len(packages))
	for _, pkg := range packages {
		names = append(names, pkg.GetName())
		if pkg.GetName() == "example.com/app" {
			app = pkg
		}
	}
	require.ElementsMatch(t, []string{"base-files", "libssl3", "example.com/app"}, names,
		"OS packages and the go binary, the symlink is not reported again")
	requireGoBinary(t, nl, app, "/usr/bin/app")
	sum := sha256.Sum256(data)
	require.Equal(t, hex.EncodeToString(sum[:]), app.GetHashes()[int32(sbom.HashAlgorithm_SHA256)],
		"the package carries the binary's checksum")
}

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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/bom/internal/generate"
	"sigs.k8s.io/bom/pkg/spdx"
)

// gomoduleFixture is the dependency-free Go module the golden tests
// also scan; offline extraction needs nothing from the network.
const gomoduleFixture = "../../test/golden/testdata/gomodule"

func TestDirectoriesGoModule(t *testing.T) {
	doc, err := generate.Document(t.Context(), &generate.Options{
		Directories: []string{gomoduleFixture},
		Offline:     true,
	})
	require.NoError(t, err)

	nl := doc.GetNodeList()
	require.Len(t, nl.GetRootElements(), 1)
	root := nl.GetNodeByID(nl.GetRootElements()[0])
	require.NotNil(t, root)
	require.Equal(t, sbom.Node_PACKAGE, root.GetType())
	require.Equal(t, "example.com/bom-golden-fixture", root.GetName())
	require.True(t,
		strings.HasPrefix(string(root.Purl()), "pkg:golang/example.com/bom-golden-fixture"),
		"root purl %q", root.Purl(),
	)
	require.Equal(t, "Apache-2.0", root.GetLicenseConcluded(),
		"the fixture LICENSE concludes the package license")

	// The four fixture files hang off the root through one contains
	// edge, each hashed with the three legacy algorithms and
	// concluding to the directory license.
	fileNames := map[string]bool{}
	for _, node := range nl.GetNodes() {
		if node.GetType() != sbom.Node_FILE {
			continue
		}
		fileNames[node.GetName()] = true
		require.True(t, strings.HasPrefix(node.GetId(), "File-"), "file id %q", node.GetId())
		for _, algo := range []sbom.HashAlgorithm{
			sbom.HashAlgorithm_SHA1, sbom.HashAlgorithm_SHA256, sbom.HashAlgorithm_SHA512,
		} {
			require.NotEmpty(t, node.GetHashes()[int32(algo)],
				"file %q missing %s", node.GetName(), algo)
		}
		if node.GetName() == "LICENSE" {
			require.Equal(t, []string{"Apache-2.0"}, node.GetLicenses())
		} else {
			require.Equal(t, []string{"NONE"}, node.GetLicenses(),
				"file %q holds no license of its own", node.GetName())
		}
		require.Equal(t, "Apache-2.0", node.GetLicenseConcluded(),
			"file %q concludes to the directory license", node.GetName())
	}
	require.Equal(t, map[string]bool{
		"go.mod": true, "main.go": true, "LICENSE": true, "README.md": true,
	}, fileNames)

	edge := nl.GetEdgeByType(root.GetId(), sbom.Edge_contains)
	require.NotNil(t, edge)
	require.Len(t, edge.GetTo(), 4)
}

func TestDirectoriesPlain(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "data.txt"), []byte("data"), os.FileMode(0o644)))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "more.txt"), []byte("more"), os.FileMode(0o644)))

	doc, err := generate.Document(t.Context(), &generate.Options{
		Directories: []string{dir},
		Offline:     true,
	})
	require.NoError(t, err)

	nl := doc.GetNodeList()
	require.Len(t, nl.GetRootElements(), 1)
	root := nl.GetNodeByID(nl.GetRootElements()[0])
	require.NotNil(t, root)
	require.Equal(t, sbom.Node_PACKAGE, root.GetType())
	require.Equal(t, filepath.Base(dir), root.GetName())
	require.Empty(t, root.Purl(), "plain directories have no purl")
	require.Empty(t, root.GetLicenseConcluded(), "no license file, nothing to conclude")

	for _, node := range nl.GetNodes() {
		if node.GetType() != sbom.Node_FILE {
			continue
		}
		require.Equal(t, []string{"NONE"}, node.GetLicenses())
		require.Empty(t, node.GetLicenseConcluded())
	}

	edge := nl.GetEdgeByType(root.GetId(), sbom.Edge_contains)
	require.NotNil(t, edge)
	require.Len(t, edge.GetTo(), 2)
}

func TestDirectoriesIgnorePatterns(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keep.txt"), []byte("keep"), os.FileMode(0o644)))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "drop.log"), []byte("drop"), os.FileMode(0o644)))

	doc, err := generate.Document(t.Context(), &generate.Options{
		Directories:    []string{dir},
		IgnorePatterns: []string{"*.log"},
		Offline:        true,
	})
	require.NoError(t, err)

	var names []string
	for _, node := range doc.GetNodeList().GetNodes() {
		if node.GetType() == sbom.Node_FILE {
			names = append(names, node.GetName())
		}
	}
	require.Equal(t, []string{"keep.txt"}, names)
}

// TestDirectoriesConvert converts a directory scan to the legacy
// model, the path the DocBuilder facade will take.
func TestDirectoriesConvert(t *testing.T) {
	doc, err := generate.Document(t.Context(), &generate.Options{
		Name:        "dir-convert",
		Namespace:   "https://sbom.k8s.io/test/dir-convert",
		Directories: []string{gomoduleFixture},
		Offline:     true,
	})
	require.NoError(t, err)

	ldoc, err := spdx.FromProtobom(doc)
	require.NoError(t, err)
	require.Len(t, ldoc.Packages, 1)
	for id, pkg := range ldoc.Packages {
		require.True(t, strings.HasPrefix(id, "SPDXRef-"), "legacy id %q", id)
		require.Equal(t, "example.com/bom-golden-fixture", pkg.Name)
		require.Equal(t, "Apache-2.0", pkg.LicenseConcluded)
		require.Empty(t, pkg.LicenseDeclared, "directories never declare a license")
		files := pkg.Files()
		require.Len(t, files, 4)
		for _, file := range files {
			require.Equal(t, "Apache-2.0", file.LicenseConcluded)
			if file.Name == "LICENSE" {
				require.Equal(t, "Apache-2.0", file.LicenseInfoInFile)
			} else {
				require.Equal(t, "NONE", file.LicenseInfoInFile, "file %q", file.Name)
			}
		}
	}
}

func TestDirectoriesNoGitignore(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".gitignore"),
		[]byte("secret.txt\n"), os.FileMode(0o644)))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "secret.txt"),
		[]byte("hidden"), os.FileMode(0o644)))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keep.txt"),
		[]byte("kept"), os.FileMode(0o644)))

	names := func(doc *sbom.Document) []string {
		var out []string
		for _, node := range doc.GetNodeList().GetNodes() {
			if node.GetType() == sbom.Node_FILE {
				out = append(out, node.GetName())
			}
		}
		return out
	}

	// By default the directory's own .gitignore is honored.
	doc, err := generate.Document(t.Context(), &generate.Options{
		Directories: []string{dir},
		Offline:     true,
	})
	require.NoError(t, err)
	require.NotContains(t, names(doc), "secret.txt")

	// With NoGitignore it is not read, and the file is indexed.
	doc, err = generate.Document(t.Context(), &generate.Options{
		Directories: []string{dir},
		NoGitignore: true,
		Offline:     true,
	})
	require.NoError(t, err)
	require.Contains(t, names(doc), "secret.txt")
	require.Contains(t, names(doc), "keep.txt")
}

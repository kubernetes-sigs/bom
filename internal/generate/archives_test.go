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
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/bom/internal/generate"
)

// writeTarball tars the given file contents into path, gzipped when
// the name asks for it.
func writeTarball(t *testing.T, path string, files map[string][]byte) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	var sink io.WriteCloser = f
	if strings.HasSuffix(path, ".gz") || strings.HasSuffix(path, ".tgz") {
		gz := gzip.NewWriter(f)
		defer gz.Close()
		sink = gz
	}
	tw := tar.NewWriter(sink)
	defer tw.Close()
	for name, content := range files {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}))
		_, err := tw.Write(content)
		require.NoError(t, err)
	}
}

// fixtureFiles reads the go module fixture's files, keyed by name.
func fixtureFiles(t *testing.T) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(gomoduleFixture)
	require.NoError(t, err)
	files := map[string][]byte{}
	for _, entry := range entries {
		content, err := os.ReadFile(filepath.Join(gomoduleFixture, entry.Name()))
		require.NoError(t, err)
		files[entry.Name()] = content
	}
	return files
}

func TestArchivesGoModule(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "fixture-src.tar.gz")
	writeTarball(t, archive, fixtureFiles(t))

	doc, err := generate.Document(t.Context(), &generate.Options{
		Archives: []string{archive},
		Offline:  true,
	})
	require.NoError(t, err)

	nl := doc.GetNodeList()
	require.Len(t, nl.GetRootElements(), 1)
	root := nl.GetNodeByID(nl.GetRootElements()[0])
	require.NotNil(t, root)
	require.Equal(t, sbom.Node_PACKAGE, root.GetType())
	require.Equal(t, "example.com/bom-golden-fixture", root.GetName(),
		"the extracted codebase keeps its module identity")
	require.Equal(t, archive, root.GetFileName(),
		"the package records the archive it was generated from")
	require.Equal(t, "Apache-2.0", root.GetLicenseConcluded())
	for _, algo := range []sbom.HashAlgorithm{
		sbom.HashAlgorithm_SHA1, sbom.HashAlgorithm_SHA256, sbom.HashAlgorithm_SHA512,
	} {
		require.NotEmpty(t, root.GetHashes()[int32(algo)],
			"archive package missing its own %s checksum", algo)
	}

	fileNames := map[string]bool{}
	for _, node := range nl.GetNodes() {
		if node.GetType() != sbom.Node_FILE {
			continue
		}
		fileNames[node.GetName()] = true
		require.Equal(t, "Apache-2.0", node.GetLicenseConcluded())
	}
	require.Equal(t, map[string]bool{
		"go.mod": true, "main.go": true, "LICENSE": true, "README.md": true,
	}, fileNames)

	edge := nl.GetEdgeByType(root.GetId(), sbom.Edge_contains)
	require.NotNil(t, edge)
	require.Len(t, edge.GetTo(), 4)
}

func TestArchivesPlain(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "data.tar")
	writeTarball(t, archive, map[string][]byte{
		"data.txt":       []byte("data"),
		"sub/nested.txt": []byte("nested"),
	})

	doc, err := generate.Document(t.Context(), &generate.Options{
		Archives: []string{archive},
		Offline:  true,
	})
	require.NoError(t, err)

	nl := doc.GetNodeList()
	require.Len(t, nl.GetRootElements(), 1)
	root := nl.GetNodeByID(nl.GetRootElements()[0])
	require.NotNil(t, root)
	require.Equal(t, "data.tar", root.GetName(),
		"packages of unrecognized trees take the archive name")
	require.Equal(t, "Package-data.tar", root.GetId())
	require.Equal(t, archive, root.GetFileName())
	require.Empty(t, root.GetLicenseConcluded())

	var names []string
	for _, node := range nl.GetNodes() {
		if node.GetType() == sbom.Node_FILE {
			names = append(names, node.GetName())
			require.Equal(t, []string{"NONE"}, node.GetLicenses())
		}
	}
	require.ElementsMatch(t, []string{"data.txt", "sub/nested.txt"}, names)
}

func TestArchivesUnsupported(t *testing.T) {
	zipPath := filepath.Join(t.TempDir(), "data.zip")
	require.NoError(t, os.WriteFile(zipPath, []byte("not a tarball"), os.FileMode(0o644)))

	_, err := generate.Document(t.Context(), &generate.Options{
		Archives: []string{zipPath},
		Offline:  true,
	})
	require.ErrorContains(t, err, "only tar archives")
}

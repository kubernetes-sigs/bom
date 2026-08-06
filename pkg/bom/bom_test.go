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

package bom_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/bom/pkg/bom"
)

func TestGenerate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact.bin")
	require.NoError(t, os.WriteFile(path, []byte("data"), os.FileMode(0o644)))

	doc, err := bom.Generate(t.Context(), &bom.GenerateOptions{
		Name:          "public-api-test",
		Namespace:     "https://sbom.k8s.io/test/public-api",
		CreatorPerson: "Jane Doe (jane@example.com)",
		Directories:   []string{"../../test/golden/testdata/gomodule"},
		Files:         []string{path},
		Offline:       true,
	})
	require.NoError(t, err)

	require.Equal(t, "public-api-test", doc.GetMetadata().GetName())
	require.Equal(t, "https://sbom.k8s.io/test/public-api", doc.GetMetadata().GetId())
	require.Len(t, doc.GetMetadata().GetAuthors(), 1)

	// One package root from the directory, one file root from the file.
	var pkgRoots, fileRoots int
	for _, node := range doc.GetNodeList().GetRootNodes() {
		switch node.GetType() {
		case sbom.Node_PACKAGE:
			pkgRoots++
		case sbom.Node_FILE:
			fileRoots++
		}
	}
	require.Equal(t, 1, pkgRoots)
	require.Equal(t, 1, fileRoots)
}

func TestGenerateNilOptions(t *testing.T) {
	doc, err := bom.Generate(t.Context(), nil)
	require.NoError(t, err)
	require.NotNil(t, doc.GetMetadata())
	require.Empty(t, doc.GetNodeList().GetNodes())
}

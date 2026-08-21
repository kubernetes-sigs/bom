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
	"crypto/sha1" //nolint:gosec // SPDX requires SHA1 file checksums
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/bom/internal/generate"
	"sigs.k8s.io/bom/pkg/spdx"
)

func TestDocumentMetadata(t *testing.T) {
	doc, err := generate.Document(t.Context(), &generate.Options{
		Name:          "engine-test",
		Namespace:     "https://sbom.k8s.io/test/engine",
		CreatorPerson: "Jane Doe (jane@example.com)",
	})
	require.NoError(t, err)

	md := doc.GetMetadata()
	require.Equal(t, "engine-test", md.GetName())
	require.Equal(t, "https://sbom.k8s.io/test/engine", md.GetId())
	require.NotNil(t, md.GetDate())
	require.Len(t, md.GetAuthors(), 1)
	require.Equal(t, "Jane Doe", md.GetAuthors()[0].GetName())
	require.Equal(t, "jane@example.com", md.GetAuthors()[0].GetEmail())
	require.Len(t, md.GetTools(), 1)
	require.Equal(t, "bom", md.GetTools()[0].GetName())
}

func TestDocumentDefaultNamespace(t *testing.T) {
	doc, err := generate.Document(t.Context(), nil)
	require.NoError(t, err)
	require.True(t,
		strings.HasPrefix(doc.GetMetadata().GetId(), "https://spdx.org/spdxdocs/k8s-releng-bom-"),
		"default namespace must keep the legacy shape, got %q", doc.GetMetadata().GetId(),
	)
	require.Empty(t, doc.GetMetadata().GetAuthors())
}

func TestDocumentFiles(t *testing.T) {
	dir := t.TempDir()
	content := []byte("hello bom\n")
	path := filepath.Join(dir, "hello.txt")
	require.NoError(t, os.WriteFile(path, content, os.FileMode(0o644)))

	doc, err := generate.Document(t.Context(), &generate.Options{Files: []string{path}})
	require.NoError(t, err)

	nodes := doc.GetNodeList().GetNodes()
	require.Len(t, nodes, 1)
	node := nodes[0]
	require.Equal(t, sbom.Node_FILE, node.GetType())
	require.Equal(t, strings.TrimPrefix(path, "/"), node.GetName())
	require.Equal(t, strings.TrimPrefix(path, "/"), node.GetFileName())
	require.Contains(t, doc.GetNodeList().GetRootElements(), node.GetId())
	require.True(t, strings.HasPrefix(node.GetId(), "File-"), "id %q", node.GetId())

	sum1 := sha1.Sum(content) //nolint:gosec // SPDX requires SHA1 file checksums
	sum256 := sha256.Sum256(content)
	sum512 := sha512.Sum512(content)
	require.Equal(t, map[int32]string{
		int32(sbom.HashAlgorithm_SHA1):   hex.EncodeToString(sum1[:]),
		int32(sbom.HashAlgorithm_SHA256): hex.EncodeToString(sum256[:]),
		int32(sbom.HashAlgorithm_SHA512): hex.EncodeToString(sum512[:]),
	}, node.GetHashes())
}

func TestDocumentFileGlobs(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.txt", "b.txt"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(name), os.FileMode(0o644)))
	}

	// A glob matching two files, a pattern matching nothing (warned,
	// not fatal) and a directory match (skipped).
	doc, err := generate.Document(t.Context(), &generate.Options{
		Files: []string{filepath.Join(dir, "*.txt"), filepath.Join(dir, "nope-*"), dir},
	})
	require.NoError(t, err)
	require.Len(t, doc.GetNodeList().GetNodes(), 2)
	require.Len(t, doc.GetNodeList().GetRootElements(), 2)
}

// TestDocumentConverts runs an engine document through the legacy
// converter, the path the DocBuilder facade will use.
func TestDocumentConverts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact.bin")
	require.NoError(t, os.WriteFile(path, []byte("data"), os.FileMode(0o644)))

	doc, err := generate.Document(t.Context(), &generate.Options{
		Name:      "convert-me",
		Namespace: "https://sbom.k8s.io/test/engine-convert",
		Files:     []string{path},
	})
	require.NoError(t, err)

	ldoc, err := spdx.FromProtobom(doc)
	require.NoError(t, err)
	require.Equal(t, "convert-me", ldoc.Name)
	require.Equal(t, "https://sbom.k8s.io/test/engine-convert", ldoc.Namespace)
	require.Len(t, ldoc.Files, 1)
	for id, file := range ldoc.Files {
		require.True(t, strings.HasPrefix(id, "SPDXRef-File-"), "legacy id %q", id)
		require.NotEmpty(t, file.Checksum["SHA256"])
	}
}

func TestElementIDSanitization(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "weird name!.txt")
	require.NoError(t, os.WriteFile(path, []byte("x"), os.FileMode(0o644)))

	doc, err := generate.Document(t.Context(), &generate.Options{Files: []string{path}})
	require.NoError(t, err)
	require.Len(t, doc.GetNodeList().GetNodes(), 1)
	id := doc.GetNodeList().GetNodes()[0].GetId()
	// Path separators become dashes, the space and bang become coded
	// escapes, and the extension dot survives.
	require.NotContains(t, id, "/")
	require.Contains(t, id, "C32")
	require.Contains(t, id, "C33")
	require.Contains(t, id, ".txt")
}

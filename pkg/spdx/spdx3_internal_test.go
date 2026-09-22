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

package spdx

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"
)

func TestPrepareSPDX3(t *testing.T) {
	doc := sbom.NewDocument()
	doc.GetNodeList().AddNode(&sbom.Node{
		Id:               "compound",
		Type:             sbom.Node_PACKAGE,
		Identifiers:      map[int32]string{int32(sbom.SoftwareIdentifierType_PURL): "pkg:deb/debian/compound@1.0"},
		Licenses:         []string{"MIT or Apache-2.0", "Zlib", "public-domain", "Zlib"},
		LicenseConcluded: "mit",
	})
	doc.GetNodeList().AddNode(&sbom.Node{
		Id:       "choice",
		Type:     sbom.Node_PACKAGE,
		Licenses: []string{"MIT", "Apache-2.0 and Zlib"},
	})
	doc.GetNodeList().AddNode(&sbom.Node{
		Id:               "noassertion",
		Type:             sbom.Node_PACKAGE,
		Licenses:         []string{NOASSERTION},
		LicenseConcluded: NOASSERTION,
	})
	doc.GetNodeList().AddNode(&sbom.Node{
		Id:               "file",
		Type:             sbom.Node_FILE,
		Licenses:         []string{NONE},
		LicenseConcluded: "Apache-2.0",
	})

	nl := prepareSPDX3(doc).GetNodeList()

	compound := nl.GetNodeByID("compound")
	require.Equal(t, []string{"(MIT OR Apache-2.0) AND Zlib AND LicenseRef-public-domain"}, compound.GetLicenses())
	require.Equal(t, "MIT", compound.GetLicenseConcluded())

	// Lists of other ecosystems offer a choice, as in SPDX 2.3.
	require.Equal(t, []string{"MIT OR (Apache-2.0 AND Zlib)"}, nl.GetNodeByID("choice").GetLicenses())

	// NOASSERTION is how SPDX 2 says nothing is asserted, which SPDX 3
	// says by leaving the license out.
	require.Empty(t, nl.GetNodeByID("noassertion").GetLicenses())
	require.Empty(t, nl.GetNodeByID("noassertion").GetLicenseConcluded())

	// NONE asserts there is no license, and is kept.
	require.Equal(t, []string{NONE}, nl.GetNodeByID("file").GetLicenses())
	require.Equal(t, "Apache-2.0", nl.GetNodeByID("file").GetLicenseConcluded())

	// The document passed in is left alone.
	require.Equal(t,
		[]string{"MIT or Apache-2.0", "Zlib", "public-domain", "Zlib"},
		doc.GetNodeList().GetNodeByID("compound").GetLicenses(),
	)
	require.Equal(t, NOASSERTION, doc.GetNodeList().GetNodeByID("noassertion").GetLicenseConcluded())
}

func TestPrepareSPDX3ExternalReferences(t *testing.T) {
	doc := sbom.NewDocument()
	doc.GetNodeList().AddNode(&sbom.Node{Id: "codebase", ExternalReferences: []*sbom.ExternalReference{
		{Type: sbom.ExternalReference_VCS, Hashes: map[int32]string{int32(sbom.HashAlgorithm_SHA1): "88d1c4b"}},
		{Type: sbom.ExternalReference_WEBSITE, Url: "https://kubernetes.io"},
	}})
	doc.GetNodeList().AddNode(&sbom.Node{Id: "none"})

	nl := prepareSPDX3(doc).GetNodeList()
	require.Len(t, nl.GetNodeByID("codebase").GetExternalReferences(), 1)
	require.Equal(t, "https://kubernetes.io", nl.GetNodeByID("codebase").GetExternalReferences()[0].GetUrl())
	require.Empty(t, nl.GetNodeByID("none").GetExternalReferences())

	// The document passed in keeps the commit hash, which other
	// formats can record.
	require.Len(t, doc.GetNodeList().GetNodeByID("codebase").GetExternalReferences(), 2)
}

func TestPrepareSPDX3Order(t *testing.T) {
	doc := sbom.NewDocument()
	nl := doc.GetNodeList()
	for _, id := range []string{"c", "a", "b"} {
		nl.AddRootNode(&sbom.Node{Id: id, Type: sbom.Node_PACKAGE})
	}
	nl.Edges = []*sbom.Edge{
		{Type: sbom.Edge_dependsOn, From: "b", To: []string{"c", "a"}},
		{Type: sbom.Edge_contains, From: "b", To: []string{"c"}},
		{Type: sbom.Edge_contains, From: "a", To: []string{"c", "b"}},
	}

	sorted := prepareSPDX3(doc).GetNodeList()
	ids := make([]string, 0, len(sorted.GetNodes()))
	for _, node := range sorted.GetNodes() {
		ids = append(ids, node.GetId())
	}
	require.Equal(t, []string{"a", "b", "c"}, ids)
	require.Equal(t, []string{"a", "b", "c"}, sorted.GetRootElements())
	require.Equal(t, []*sbom.Edge{
		{Type: sbom.Edge_contains, From: "a", To: []string{"b", "c"}},
		{Type: sbom.Edge_contains, From: "b", To: []string{"c"}},
		{Type: sbom.Edge_dependsOn, From: "b", To: []string{"a", "c"}},
	}, sorted.GetEdges())

	// The document passed in is left alone.
	require.Equal(t, []string{"c", "a", "b"}, nl.GetRootElements())
	require.Equal(t, []string{"c", "a"}, nl.GetEdges()[0].GetTo())
}

func TestGenerateProtobomOrganization(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact.bin")
	require.NoError(t, os.WriteFile(path, []byte("data"), os.FileMode(0o644)))
	pdoc, err := NewDocBuilder().GenerateProtobom(&DocGenerateOptions{
		CreatorPerson: "Jane Doe (jane@example.com)",
		Files:         []string{path},
	})
	require.NoError(t, err)
	authors := pdoc.GetMetadata().GetAuthors()
	require.Len(t, authors, 2)
	require.Equal(t, "Jane Doe", authors[0].GetName())
	require.Equal(t, defaultDocumentOrganization, authors[1].GetName())
	require.True(t, authors[1].GetIsOrg())
}

func TestWriteSPDX3NilDocument(t *testing.T) {
	require.Error(t, WriteSPDX3(nil, nil))
}

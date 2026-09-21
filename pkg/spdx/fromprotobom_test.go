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

package spdx_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"sigs.k8s.io/bom/pkg/serialize"
	"sigs.k8s.io/bom/pkg/spdx"
)

// testDocument builds a protobom document with one root package
// containing a file.
func testDocument(t *testing.T) *sbom.Document {
	t.Helper()
	doc := sbom.NewDocument()
	doc.Metadata.Id = "https://sbom.k8s.io/test/convert#SPDXRef-DOCUMENT"
	doc.Metadata.Name = "convert-test"
	doc.Metadata.Date = timestamppb.New(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	doc.Metadata.Authors = []*sbom.Person{
		{Name: "Jane Doe", Email: "jane@example.com"},
		{Name: "Kubernetes Release Engineering", IsOrg: true},
	}
	doc.Metadata.Tools = []*sbom.Tool{{Name: "bom", Version: "v1.0.0"}}

	pkg := &sbom.Node{
		Id:               "Package-nginx",
		Type:             sbom.Node_PACKAGE,
		Name:             "nginx",
		Version:          "1.25.3",
		UrlHome:          "https://nginx.org",
		UrlDownload:      "https://nginx.org/download/nginx-1.25.3.tar.gz",
		LicenseConcluded: "BSD-2-Clause",
		Licenses:         []string{"BSD-2-Clause"},
		Copyright:        "Copyright (C) Igor Sysoev\n",
		PrimaryPurpose:   []sbom.Purpose{sbom.Purpose_CONTAINER},
		Suppliers:        []*sbom.Person{{Name: "F5, Inc.", IsOrg: true}},
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): "pkg:oci/nginx@1.25.3",
		},
		Hashes: map[int32]string{
			int32(sbom.HashAlgorithm_SHA256): "9f7fd60e5346e9b6b9e6dbc769ffca94a394a5253bb45a2cbca4fbe3f4d34a0f",
		},
	}
	doc.GetNodeList().AddRootNode(pkg)

	file := &sbom.Node{
		Id:       "File-nginx.conf",
		Type:     sbom.Node_FILE,
		Name:     "etc/nginx/nginx.conf",
		Licenses: []string{"BSD-2-Clause"},
		Hashes: map[int32]string{
			int32(sbom.HashAlgorithm_SHA1):   "f572d396fae9206628714fb2ce00f72e94f2258f",
			int32(sbom.HashAlgorithm_SHA256): "b40930bbcf80744c86c46a12bc9da056641d722716c378f5659b9e555ef833e1",
		},
	}
	require.NoError(t, doc.GetNodeList().RelateNodeAtID(file, "Package-nginx", sbom.Edge_contains))
	return doc
}

func TestToSPDXMetadata(t *testing.T) {
	doc, err := spdx.FromProtobom(testDocument(t))
	require.NoError(t, err)

	require.Equal(t, "convert-test", doc.Name)
	require.Equal(t, "https://sbom.k8s.io/test/convert", doc.Namespace)
	require.Equal(t, "SPDXRef-DOCUMENT", doc.ID)
	require.Equal(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), doc.Created)
	require.Equal(t, "Jane Doe (jane@example.com)", doc.Creator.Person)
	require.Equal(t, "Kubernetes Release Engineering", doc.Creator.Organization)
	require.Equal(t, []string{"bom-v1.0.0"}, doc.Creator.Tool)
}

func TestToSPDXNamespaces(t *testing.T) {
	for name, tc := range map[string]struct {
		id       string
		expected string
	}{
		"empty stays empty":  {"", ""},
		"fragment stripped":  {"https://example.com/doc#SPDXRef-DOCUMENT", "https://example.com/doc"},
		"plain uri verbatim": {"https://example.com/doc", "https://example.com/doc"},
		// Non-URI IDs map to the same deterministic urn protobom's
		// serializer generates from its namespace UUID.
		"non-uri to urn": {"some plain string", "urn:uuid:e52eaccd-4143-5bee-8cc0-8ed4ab2eced8"},
	} {
		t.Run(name, func(t *testing.T) {
			pdoc := sbom.NewDocument()
			pdoc.Metadata.Id = tc.id
			doc, err := spdx.FromProtobom(pdoc)
			require.NoError(t, err)
			require.Equal(t, tc.expected, doc.Namespace)
		})
	}
}

func TestToSPDXPackage(t *testing.T) {
	doc, err := spdx.FromProtobom(testDocument(t))
	require.NoError(t, err)

	require.Len(t, doc.Packages, 1)
	pkg := doc.Packages["SPDXRef-Package-nginx"]
	require.NotNil(t, pkg, "root package not keyed by prefixed SPDX ID")
	require.Equal(t, "nginx", pkg.Name)
	require.Equal(t, "1.25.3", pkg.Version)
	require.Equal(t, "https://nginx.org", pkg.HomePage)
	require.Equal(t, "https://nginx.org/download/nginx-1.25.3.tar.gz", pkg.DownloadLocation)
	require.Equal(t, "BSD-2-Clause", pkg.LicenseConcluded)
	require.Equal(t, "BSD-2-Clause", pkg.LicenseDeclared)
	require.Equal(t, "Copyright (C) Igor Sysoev", pkg.CopyrightText)
	require.Equal(t, "CONTAINER", pkg.PrimaryPurpose)
	require.Equal(t, "F5, Inc.", pkg.Supplier.Organization)
	require.Empty(t, pkg.Supplier.Person)
	require.Equal(t,
		map[string]string{"SHA256": "9f7fd60e5346e9b6b9e6dbc769ffca94a394a5253bb45a2cbca4fbe3f4d34a0f"},
		pkg.Checksum,
	)
	require.Equal(t,
		[]spdx.ExternalRef{{Category: "PACKAGE-MANAGER", Type: "purl", Locator: "pkg:oci/nginx@1.25.3"}},
		pkg.ExternalRefs,
	)
	require.Equal(t, "pkg:oci/nginx@1.25.3", pkg.Purl().String())
}

func TestToSPDXNestedFile(t *testing.T) {
	doc, err := spdx.FromProtobom(testDocument(t))
	require.NoError(t, err)

	// The contained file hangs off the package, not the document.
	require.Empty(t, doc.Files)
	pkg := doc.Packages["SPDXRef-Package-nginx"]
	require.NotNil(t, pkg)

	rels := *pkg.GetRelationships()
	require.Len(t, rels, 1)
	rel := rels[0]
	require.Equal(t, spdx.CONTAINS, rel.Type)
	require.True(t, rel.FullRender, "the only edge to the file must carry its rendering")

	file, ok := rel.Peer.(*spdx.File)
	require.True(t, ok, "peer is not a file")
	require.Equal(t, "SPDXRef-File-nginx.conf", file.SPDXID())
	require.Equal(t, "etc/nginx/nginx.conf", file.Name)
	require.Equal(t, "BSD-2-Clause", file.LicenseInfoInFile)
	require.Equal(t, map[string]string{
		"SHA1":   "f572d396fae9206628714fb2ce00f72e94f2258f",
		"SHA256": "b40930bbcf80744c86c46a12bc9da056641d722716c378f5659b9e555ef833e1",
	}, file.Checksum)
}

func TestToSPDXRootFile(t *testing.T) {
	pdoc := sbom.NewDocument()
	pdoc.Metadata.Name = "root-file-doc"
	pdoc.GetNodeList().AddRootNode(&sbom.Node{
		Id:   "File-readme",
		Type: sbom.Node_FILE,
		Name: "README.md",
	})

	doc, err := spdx.FromProtobom(pdoc)
	require.NoError(t, err)
	require.Empty(t, doc.Packages)
	require.Len(t, doc.Files, 1)
	require.NotNil(t, doc.Files["SPDXRef-File-readme"])
}

// TestToSPDXFullRenderOnce checks that a node reachable through two
// edges gets exactly one rendering edge, and that edge types map to
// the SPDX relationship vocabulary.
func TestToSPDXFullRenderOnce(t *testing.T) {
	pdoc := sbom.NewDocument()
	pdoc.Metadata.Name = "diamond-doc"
	shared := &sbom.Node{Id: "libfoo", Type: sbom.Node_PACKAGE, Name: "libfoo"}
	for _, id := range []string{"app-a", "app-b"} {
		pdoc.GetNodeList().AddRootNode(&sbom.Node{Id: id, Type: sbom.Node_PACKAGE, Name: id})
	}
	pdoc.GetNodeList().AddNode(shared)
	pdoc.GetNodeList().AddEdge(&sbom.Edge{Type: sbom.Edge_contains, From: "app-a", To: []string{"libfoo"}})
	pdoc.GetNodeList().AddEdge(&sbom.Edge{Type: sbom.Edge_dependsOn, From: "app-b", To: []string{"libfoo"}})

	doc, err := spdx.FromProtobom(pdoc)
	require.NoError(t, err)
	require.Len(t, doc.Packages, 2)

	relA := *doc.Packages["SPDXRef-app-a"].GetRelationships()
	relB := *doc.Packages["SPDXRef-app-b"].GetRelationships()
	require.Len(t, relA, 1)
	require.Len(t, relB, 1)
	require.Equal(t, spdx.CONTAINS, relA[0].Type)
	require.Equal(t, spdx.DEPENDS_ON, relB[0].Type)
	require.Same(t, relA[0].Peer, relB[0].Peer, "both edges must point at the same object")

	fullRenders := 0
	for _, rel := range []*spdx.Relationship{relA[0], relB[0]} {
		if rel.FullRender {
			fullRenders++
		}
	}
	require.Equal(t, 1, fullRenders, "the shared node must render exactly once")
}

// TestToSPDXPromotion checks that nodes unreachable from the roots
// become top-level elements: plain orphans and cycle members alike.
func TestToSPDXPromotion(t *testing.T) {
	pdoc := sbom.NewDocument()
	pdoc.Metadata.Name = "promotion-doc"
	pdoc.GetNodeList().AddNode(&sbom.Node{Id: "orphan", Type: sbom.Node_PACKAGE, Name: "orphan"})
	pdoc.GetNodeList().AddNode(&sbom.Node{Id: "cycle-a", Type: sbom.Node_PACKAGE, Name: "cycle-a"})
	pdoc.GetNodeList().AddNode(&sbom.Node{Id: "cycle-b", Type: sbom.Node_PACKAGE, Name: "cycle-b"})
	pdoc.GetNodeList().AddEdge(&sbom.Edge{Type: sbom.Edge_contains, From: "cycle-a", To: []string{"cycle-b"}})
	pdoc.GetNodeList().AddEdge(&sbom.Edge{Type: sbom.Edge_contains, From: "cycle-b", To: []string{"cycle-a"}})

	doc, err := spdx.FromProtobom(pdoc)
	require.NoError(t, err)

	// The orphan and the first cycle member become roots; the second
	// cycle member renders through the first.
	require.Len(t, doc.Packages, 2)
	require.NotNil(t, doc.Packages["SPDXRef-orphan"])
	require.NotNil(t, doc.Packages["SPDXRef-cycle-a"])

	// The cycle's back edge must not render the root again, and the
	// document must render without infinite recursion.
	back := *doc.Packages["SPDXRef-cycle-a"].GetRelationships()
	require.Len(t, back, 1)
	require.True(t, back[0].FullRender)
	cycleB, ok := back[0].Peer.(*spdx.Package)
	require.True(t, ok)
	require.False(t, (*cycleB.GetRelationships())[0].FullRender)

	_, err = doc.Render()
	require.NoError(t, err)
}

// TestToSPDXSerializers runs a converted document through both legacy
// serializers and reparses the tag-value output with the legacy
// parser, the same paths bom's API consumers exercise.
func TestToSPDXSerializers(t *testing.T) {
	doc, err := spdx.FromProtobom(testDocument(t))
	require.NoError(t, err)

	tv, err := (&serialize.TagValue{}).Serialize(doc)
	require.NoError(t, err)
	for _, expected := range []string{
		"DocumentNamespace: https://sbom.k8s.io/test/convert",
		"Creator: Person: Jane Doe (jane@example.com)",
		"Creator: Tool: bom-v1.0.0",
		"PackageName: nginx",
		"ExternalRef: PACKAGE-MANAGER purl pkg:oci/nginx@1.25.3",
		"FileName: etc/nginx/nginx.conf",
		"Relationship: SPDXRef-Package-nginx CONTAINS SPDXRef-File-nginx.conf",
		"Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-nginx",
	} {
		require.Contains(t, tv, expected+"\n")
	}

	// The JSON serializer walks the relationship graph through the
	// Peer pointers; it must find every element live.
	jsonDoc, err := (&serialize.JSON{}).Serialize(doc)
	require.NoError(t, err)
	require.Contains(t, jsonDoc, `"name": "nginx"`)
	require.Contains(t, jsonDoc, `"fileName": "etc/nginx/nginx.conf"`)

	path := filepath.Join(t.TempDir(), "converted.spdx")
	require.NoError(t, os.WriteFile(path, []byte(tv), os.FileMode(0o644)))
	reparsed, err := spdx.OpenDoc(path)
	require.NoError(t, err)
	require.Len(t, reparsed.Packages, 1)
}

func TestToSPDXNilGuards(t *testing.T) {
	_, err := spdx.FromProtobom(nil)
	require.Error(t, err)
	_, err = spdx.FromProtobom(&sbom.Document{})
	require.Error(t, err)
	// A document with no node list converts to an empty document.
	doc, err := spdx.FromProtobom(&sbom.Document{Metadata: &sbom.Metadata{Name: "empty"}})
	require.NoError(t, err)
	require.Empty(t, doc.Packages)
	require.Empty(t, doc.Files)
}

// TestFromProtobomSetsFileName pins that converted files carry a file
// name. Validation matches files on it, so a document whose files have
// only a Name validates nothing.
func TestFromProtobomSetsFileName(t *testing.T) {
	pdoc := &sbom.Document{
		Metadata: &sbom.Metadata{Id: "https://sbom.k8s.io/test/filename"},
		NodeList: &sbom.NodeList{
			Nodes: []*sbom.Node{
				{Id: "File-both", Type: sbom.Node_FILE, Name: "a.txt", FileName: "a.txt"},
				{Id: "File-name-only", Type: sbom.Node_FILE, Name: "b.txt"},
			},
			RootElements: []string{"File-both", "File-name-only"},
		},
	}

	doc, err := spdx.FromProtobom(pdoc)
	require.NoError(t, err)
	require.Len(t, doc.Files, 2)

	for id, file := range doc.Files {
		require.NotEmpty(t, file.FileName, "file %q has no file name", id)
		require.Equal(t, file.Name, file.FileName,
			"a node carrying only a name falls back to it")
	}
}

// TestToSPDXFilesRenderBeforeDependencies checks the tag-value element
// order of a package holding files and depending on packages. A file
// belongs to the package listed last before it, so the files have to
// render right under their package, ahead of its dependencies, whatever
// the order of the edges.
func TestToSPDXFilesRenderBeforeDependencies(t *testing.T) {
	pdoc := sbom.NewDocument()
	pdoc.Metadata.Id = "https://sbom.k8s.io/test/order"
	pdoc.Metadata.Name = "order-doc"
	nl := pdoc.GetNodeList()
	nl.AddRootNode(&sbom.Node{Id: "Package-app", Type: sbom.Node_PACKAGE, Name: "app"})
	nl.AddNode(&sbom.Node{Id: "Package-dep", Type: sbom.Node_PACKAGE, Name: "dep"})
	nl.AddNode(&sbom.Node{Id: "Package-old", Type: sbom.Node_PACKAGE, Name: "old"})
	nl.AddNode(&sbom.Node{
		Id: "File-main.go", Type: sbom.Node_FILE, Name: "main.go",
		Hashes: map[int32]string{int32(sbom.HashAlgorithm_SHA1): "f572d396fae9206628714fb2ce00f72e94f2258f"},
	})
	// The relationships of a node are ordered by type: ANCESTOR_OF comes
	// before CONTAINS, and DEPENDS_ON after it.
	nl.AddEdge(&sbom.Edge{Type: sbom.Edge_ancestor, From: "Package-app", To: []string{"Package-old"}})
	nl.AddEdge(&sbom.Edge{Type: sbom.Edge_dependsOn, From: "Package-app", To: []string{"Package-dep"}})
	nl.AddEdge(&sbom.Edge{Type: sbom.Edge_contains, From: "Package-app", To: []string{"File-main.go"}})

	doc, err := spdx.FromProtobom(pdoc)
	require.NoError(t, err)
	tv, err := (&serialize.TagValue{}).Serialize(doc)
	require.NoError(t, err)

	app := strings.Index(tv, "SPDXID: SPDXRef-Package-app\n")
	file := strings.Index(tv, "SPDXID: SPDXRef-File-main.go\n")
	dep := strings.Index(tv, "SPDXID: SPDXRef-Package-dep\n")
	old := strings.Index(tv, "SPDXID: SPDXRef-Package-old\n")
	require.Positive(t, app)
	require.Greater(t, file, app, "the file renders after its package")
	require.Greater(t, dep, file, "related packages render after the files of the package")
	require.Greater(t, old, file, "related packages render after the files of the package")
}

// TestToSPDXLicenseNormalization checks that the licenses package
// managers declare turn into valid SPDX expressions, with extracted
// licensing information for the ones not on the SPDX license list, in
// both serializations.
func TestToSPDXLicenseNormalization(t *testing.T) {
	pdoc := sbom.NewDocument()
	pdoc.Metadata.Id = "https://sbom.k8s.io/test/licenses"
	pdoc.Metadata.Name = "licenses-doc"
	pdoc.GetNodeList().AddRootNode(&sbom.Node{
		Id:               "Package-coreutils",
		Type:             sbom.Node_PACKAGE,
		Name:             "coreutils",
		LicenseConcluded: "GPL-3+",
		Licenses:         []string{"GPL-3.0-or-later", "public-domain", "GPL-3+ with Autoconf-data exception"},
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): "pkg:deb/debian/coreutils@9.1-1?arch=amd64",
		},
	})
	// A composer license list is a choice.
	pdoc.GetNodeList().AddRootNode(&sbom.Node{
		Id:       "Package-composer",
		Type:     sbom.Node_PACKAGE,
		Name:     "vendor/lib",
		Licenses: []string{"LGPL-2.1-only", "GPL-3.0-or-later"},
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): "pkg:composer/vendor/lib@1.0.0",
		},
	})
	pdoc.GetNodeList().AddRootNode(&sbom.Node{Id: "File-readme", Type: sbom.Node_FILE, Name: "README"})
	// The licenses found in a file are listed one by one.
	pdoc.GetNodeList().AddRootNode(&sbom.Node{
		Id: "File-src", Type: sbom.Node_FILE, Name: "src.c",
		Licenses: []string{"MIT OR Apache-2.0", "custom"},
	})

	doc, err := spdx.FromProtobom(pdoc)
	require.NoError(t, err)
	pkg := doc.Packages["SPDXRef-Package-coreutils"]
	require.NotNil(t, pkg)
	require.Equal(t,
		"GPL-3.0-or-later AND LicenseRef-public-domain AND LicenseRef-GPL-3-or-later-with-Autoconf-data-exception",
		pkg.LicenseDeclared,
	)
	require.Equal(t, "LicenseRef-GPL-3-or-later", pkg.LicenseConcluded)
	require.Equal(t, "LGPL-2.1-only OR GPL-3.0-or-later", doc.Packages["SPDXRef-Package-composer"].LicenseDeclared)
	require.Equal(t, "(MIT OR Apache-2.0) AND LicenseRef-custom", doc.Files["SPDXRef-File-src"].LicenseInfoInFile)
	ids := make([]string, 0, len(doc.ExtractedLicenses))
	for _, lic := range doc.ExtractedLicenses {
		ids = append(ids, lic.ID)
	}
	require.Equal(t, []string{
		"LicenseRef-GPL-3-or-later", "LicenseRef-GPL-3-or-later-with-Autoconf-data-exception",
		"LicenseRef-custom", "LicenseRef-public-domain",
	}, ids)

	tv, err := (&serialize.TagValue{}).Serialize(doc)
	require.NoError(t, err)
	require.Contains(t, tv, "LicenseID: LicenseRef-public-domain\nExtractedText: <text>")
	require.Contains(t, tv, "LicenseName: public-domain\n")
	require.Contains(t, tv, "LicenseInfoInFile: Apache-2.0\nLicenseInfoInFile: LicenseRef-custom\nLicenseInfoInFile: MIT\n")
	require.Greater(t, strings.Index(tv, "LicenseID:"), strings.LastIndex(tv, "PackageName:"),
		"tag-value lists the extracted licenses after the elements")

	jsonDoc, err := (&serialize.JSON{}).Serialize(doc)
	require.NoError(t, err)
	var parsed struct {
		Extracted []struct {
			ID   string `json:"licenseId"`
			Text string `json:"extractedText"`
			Name string `json:"name"`
		} `json:"hasExtractedLicensingInfos"`
		Files []struct {
			LicenseInfoInFiles []string `json:"licenseInfoInFiles"`
		} `json:"files"`
	}
	require.NoError(t, json.Unmarshal([]byte(jsonDoc), &parsed))
	require.Len(t, parsed.Extracted, 4)
	require.Equal(t, "LicenseRef-GPL-3-or-later", parsed.Extracted[0].ID)
	require.Equal(t, "GPL-3+", parsed.Extracted[0].Name)
	require.NotEmpty(t, parsed.Extracted[0].Text)

	// A file with no license data asserts nothing rather than listing
	// an empty license.
	require.Len(t, parsed.Files, 2)
	require.Equal(t, []string{"NOASSERTION"}, parsed.Files[0].LicenseInfoInFiles)
	require.Equal(t, []string{"Apache-2.0", "LicenseRef-custom", "MIT"}, parsed.Files[1].LicenseInfoInFiles)

	// Reading the document back keeps its license expressions and
	// fabricates no extracted licensing information: protobom does not
	// carry the original texts.
	path := filepath.Join(t.TempDir(), "licenses.spdx")
	require.NoError(t, os.WriteFile(path, []byte(tv), os.FileMode(0o644)))
	reparsed, err := spdx.OpenDoc(path)
	require.NoError(t, err)
	require.Empty(t, reparsed.ExtractedLicenses)
	require.Equal(t, pkg.LicenseDeclared, reparsed.Packages["SPDXRef-Package-coreutils"].LicenseDeclared)
}

// TestToSPDXExtractedLicenseTagValue checks that license names which
// would break the tag-value syntax are defused.
func TestToSPDXExtractedLicenseTagValue(t *testing.T) {
	doc := spdx.NewDocument()
	doc.ExtractedLicenses = []spdx.ExtractedLicense{{
		ID:   "LicenseRef-evil",
		Name: "line one\nline two </text>",
		Text: "text with </text> inside <TEXT>",
	}}
	tv, err := doc.Render()
	require.NoError(t, err)
	require.Contains(t, tv, "LicenseName: line one line two </text>\n")
	require.Contains(t, tv, "ExtractedText: <text>text with  inside </text>\n")
}

// TestToSPDXExternalReferenceTypes checks that external references of
// types SPDX does not define keep their type name.
func TestToSPDXExternalReferenceTypes(t *testing.T) {
	pdoc := sbom.NewDocument()
	pdoc.Metadata.Name = "extref-doc"
	pdoc.GetNodeList().AddRootNode(&sbom.Node{
		Id:   "Package-yaml",
		Type: sbom.Node_PACKAGE,
		Name: "go.yaml.in/yaml/v3",
		ExternalReferences: []*sbom.ExternalReference{
			{Type: sbom.ExternalReference_VCS, Url: "https://github.com/yaml/go-yaml"},
			{Type: sbom.ExternalReference_OTHER, Url: "https://example.com/other"},
			{Type: sbom.ExternalReference_SECURITY_SWID, Url: "swid:2df9de35-0aff-4a86-ace6-f7dddd1ade4c"},
		},
	})

	doc, err := spdx.FromProtobom(pdoc)
	require.NoError(t, err)
	require.Equal(t, []spdx.ExternalRef{
		{Category: "OTHER", Type: "vcs", Locator: "https://github.com/yaml/go-yaml"},
		{Category: "OTHER", Type: "OTHER", Locator: "https://example.com/other"},
		{Category: "SECURITY", Type: "swid", Locator: "swid:2df9de35-0aff-4a86-ace6-f7dddd1ade4c"},
	}, doc.Packages["SPDXRef-Package-yaml"].ExternalRefs)

	// The type survives the way back to protobom.
	back, err := spdx.ToProtobom(doc)
	require.NoError(t, err)
	node := back.GetNodeList().GetNodeByID("Package-yaml")
	require.NotNil(t, node)
	require.Equal(t, sbom.ExternalReference_VCS, node.GetExternalReferences()[0].GetType())
	require.Equal(t, sbom.ExternalReference_SECURITY_SWID, node.GetExternalReferences()[2].GetType())
}

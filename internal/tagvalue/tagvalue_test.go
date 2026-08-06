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

package tagvalue_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"sigs.k8s.io/bom/internal/tagvalue"
	bomspdx "sigs.k8s.io/bom/pkg/spdx"
)

// testDocument builds a small protobom document with a package
// containing a file.
func testDocument(t *testing.T) *sbom.Document {
	t.Helper()
	doc := sbom.NewDocument()
	doc.Metadata.Id = "https://sbom.k8s.io/test/tagvalue#SPDXRef-DOCUMENT"
	doc.Metadata.Name = "tagvalue-test"
	doc.Metadata.Date = timestamppb.New(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	pkg := &sbom.Node{
		Id:               "Package-nginx",
		Type:             sbom.Node_PACKAGE,
		Name:             "nginx",
		Version:          "1.25.3",
		LicenseConcluded: "Apache-2.0",
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): "pkg:oci/nginx@1.25.3",
		},
		Hashes: map[int32]string{
			int32(sbom.HashAlgorithm_SHA256): "9f7fd60e5346e9b6b9e6dbc769ffca94a394a5253bb45a2cbca4fbe3f4d34a0f",
		},
	}
	doc.GetNodeList().AddRootNode(pkg)

	file := &sbom.Node{
		Id:   "File-nginx.conf",
		Type: sbom.Node_FILE,
		Name: "etc/nginx/nginx.conf",
		Hashes: map[int32]string{
			int32(sbom.HashAlgorithm_SHA256): "b40930bbcf80744c86c46a12bc9da056641d722716c378f5659b9e555ef833e1",
		},
	}
	require.NoError(t, doc.GetNodeList().RelateNodeAtID(file, "Package-nginx", sbom.Edge_contains))
	return doc
}

func render(t *testing.T, doc *sbom.Document) string {
	t.Helper()
	s := tagvalue.NewSerializer()
	raw, err := s.Serialize(doc, nil, nil)
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, s.Render(raw, &buf, nil, nil))
	return buf.String()
}

func TestRenderOutput(t *testing.T) {
	tv := render(t, testDocument(t))
	for _, expected := range []string{
		"SPDXVersion: SPDX-2.3",
		"DocumentNamespace: https://sbom.k8s.io/test/tagvalue",
		"PackageName: nginx",
		"PackageVersion: 1.25.3",
		"ExternalRef: PACKAGE-MANAGER purl pkg:oci/nginx@1.25.3",
		"FileName: etc/nginx/nginx.conf",
	} {
		require.Contains(t, tv, expected+"\n")
	}
}

// TestLegacyParserReadsRendering feeds the tag-value rendering to bom's
// current hand-rolled parser: documents written through protobom must
// remain readable by every bom release consuming SBOMs today.
func TestLegacyParserReadsRendering(t *testing.T) {
	tv := render(t, testDocument(t))
	path := filepath.Join(t.TempDir(), "test.spdx")
	require.NoError(t, os.WriteFile(path, []byte(tv), os.FileMode(0o644)))

	doc, err := bomspdx.OpenDoc(path)
	require.NoError(t, err)
	require.NotNil(t, doc)

	var nginx *bomspdx.Package
	for _, p := range doc.Packages {
		if p.Name == "nginx" {
			nginx = p
		}
	}
	require.NotNil(t, nginx, "nginx package not found in reparsed document")
	require.Equal(t, "1.25.3", nginx.Version)
	require.Equal(t, "pkg:oci/nginx@1.25.3", nginx.Purl().String())

	// The file must hang off the package through a relationship.
	found := false
	for _, rel := range *nginx.GetRelationships() {
		if rel.Peer != nil && rel.Peer.GetName() == "etc/nginx/nginx.conf" {
			found = true
		}
	}
	require.True(t, found, "contained file not related to the nginx package")
}

// TestUnserializeLegacyRendering parses tag-value produced by bom's
// current template renderer: the unserializer must read the SBOMs bom
// has been publishing (the Kubernetes release SBOM format).
func TestUnserializeLegacyRendering(t *testing.T) {
	ldoc := bomspdx.NewDocument()
	ldoc.Name = "legacy-doc"
	ldoc.Namespace = "https://sbom.k8s.io/test/legacy"

	pkg := bomspdx.NewPackage()
	pkg.SetSPDXID("SPDXRef-Package-kubectl")
	pkg.Name = "kubectl"
	pkg.Version = "v1.33.0"
	pkg.LicenseConcluded = "Apache-2.0"
	require.NoError(t, ldoc.AddPackage(pkg))

	file := bomspdx.NewFile()
	file.SetSPDXID("SPDXRef-File-kubectl-bin")
	file.Name = "bin/kubectl"
	file.Checksum = map[string]string{
		"SHA256": "e5f7a7ed445673057c73686cb846e0c33ff0d5701fd43bf6aff16bb39ae14de2",
	}
	require.NoError(t, pkg.AddFile(file))

	tv, err := ldoc.Render()
	require.NoError(t, err)

	pbom, err := tagvalue.NewUnserializer().Unserialize(strings.NewReader(tv), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, pbom)
	require.Equal(t, "legacy-doc", pbom.GetMetadata().GetName())

	var pkgNode, fileNode *sbom.Node
	for _, n := range pbom.GetNodeList().GetNodes() {
		switch n.GetName() {
		case "kubectl":
			pkgNode = n
		case "bin/kubectl":
			fileNode = n
		}
	}
	require.NotNil(t, pkgNode, "kubectl package node not found")
	require.NotNil(t, fileNode, "kubectl file node not found")
	require.Equal(t, "v1.33.0", pkgNode.GetVersion())
	require.Equal(t, sbom.Node_FILE, fileNode.GetType())

	// The CONTAINS relationship must survive as an edge.
	related := false
	for _, edge := range pbom.GetNodeList().GetEdges() {
		if edge.GetFrom() == pkgNode.GetId() {
			for _, to := range edge.GetTo() {
				if to == fileNode.GetId() {
					related = true
				}
			}
		}
	}
	require.True(t, related, "package -> file edge not found")
}

func TestRoundTrip(t *testing.T) {
	original := testDocument(t)
	tv := render(t, original)

	doc, err := tagvalue.NewUnserializer().Unserialize(strings.NewReader(tv), nil, nil)
	require.NoError(t, err)

	require.Len(t, doc.GetNodeList().GetNodes(), 2)
	var pkgNode, fileNode *sbom.Node
	for _, n := range doc.GetNodeList().GetNodes() {
		switch n.GetType() {
		case sbom.Node_PACKAGE:
			pkgNode = n
		case sbom.Node_FILE:
			fileNode = n
		}
	}
	require.NotNil(t, pkgNode)
	require.NotNil(t, fileNode)
	require.Equal(t, "nginx", pkgNode.GetName())
	require.Equal(t, "1.25.3", pkgNode.GetVersion())
	require.Equal(t, "Apache-2.0", pkgNode.GetLicenseConcluded())
	require.Equal(t, "pkg:oci/nginx@1.25.3", pkgNode.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)])
	require.Equal(t,
		"9f7fd60e5346e9b6b9e6dbc769ffca94a394a5253bb45a2cbca4fbe3f4d34a0f",
		pkgNode.GetHashes()[int32(sbom.HashAlgorithm_SHA256)],
	)
	require.Equal(t, "etc/nginx/nginx.conf", fileNode.GetName())
}

// TestRegister exercises the format through protobom's public writer
// entry point, as future bom code will use it.
func TestRegister(t *testing.T) {
	tagvalue.Register()
	var buf bytes.Buffer
	w := writer.New(writer.WithFormat(formats.SPDX23TV))
	require.NoError(t, w.WriteStream(testDocument(t), &buf))
	require.Contains(t, buf.String(), "SPDXVersion: SPDX-2.3\n")
	require.Contains(t, buf.String(), "PackageName: nginx\n")
}

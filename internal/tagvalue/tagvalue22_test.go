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
	"strings"
	"testing"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
	v2_2 "github.com/spdx/tools-golang/spdx/v2/v2_2"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/bom/internal/tagvalue"
	bomspdx "sigs.k8s.io/bom/pkg/spdx"
)

func render22TV(t *testing.T, doc *sbom.Document) string {
	t.Helper()
	s := tagvalue.NewSerializer22TV()
	raw, err := s.Serialize(doc, nil, nil)
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, s.Render(raw, &buf, nil, nil))
	return buf.String()
}

func TestSerialize22(t *testing.T) {
	raw, err := tagvalue.NewSerializer22().Serialize(testDocument(t), nil, nil)
	require.NoError(t, err)

	doc22, ok := raw.(*v2_2.Document)
	require.True(t, ok, "serialized document is not SPDX 2.2")
	require.Equal(t, v2_2.Version, doc22.SPDXVersion)

	require.Len(t, doc22.Packages, 1)
	pkg := doc22.Packages[0]
	require.Equal(t, "nginx", pkg.PackageName)
	require.Equal(t, "Apache-2.0", pkg.PackageLicenseConcluded)
	// Optional in 2.3, required in 2.2: backfilled on downgrade.
	require.Equal(t, "NOASSERTION", pkg.PackageLicenseDeclared)
	require.NotEmpty(t, pkg.PackageCopyrightText)

	require.Len(t, doc22.Files, 1)
	file := doc22.Files[0]
	require.Equal(t, "etc/nginx/nginx.conf", file.FileName)
	require.Equal(t, "NOASSERTION", file.LicenseConcluded)
	require.Equal(t, []string{"NOASSERTION"}, file.LicenseInfoInFiles)
	require.NotEmpty(t, file.FileCopyrightText)
}

func TestRender22JSON(t *testing.T) {
	s := tagvalue.NewSerializer22()
	raw, err := s.Serialize(testDocument(t), nil, nil)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, s.Render(raw, &buf, nil, nil))
	require.Contains(t, buf.String(), `"spdxVersion":"SPDX-2.2"`)
	require.Contains(t, buf.String(), `"name":"nginx"`)
}

func TestRender22TV(t *testing.T) {
	tv := render22TV(t, testDocument(t))
	for _, expected := range []string{
		"SPDXVersion: SPDX-2.2",
		"PackageName: nginx",
		"PackageVersion: 1.25.3",
		"FileName: etc/nginx/nginx.conf",
	} {
		require.Contains(t, tv, expected+"\n")
	}
}

// TestRoundTrip22 writes a document as SPDX 2.2 tag-value and reads it
// back through the 2.2 unserializer.
func TestRoundTrip22(t *testing.T) {
	tv := render22TV(t, testDocument(t))

	doc, err := tagvalue.NewUnserializer22TV().Unserialize(strings.NewReader(tv), nil, nil)
	require.NoError(t, err)
	require.Len(t, doc.GetNodeList().GetNodes(), 2)

	var pkgNode *sbom.Node
	for _, n := range doc.GetNodeList().GetNodes() {
		if n.GetType() == sbom.Node_PACKAGE {
			pkgNode = n
		}
	}
	require.NotNil(t, pkgNode)
	require.Equal(t, "nginx", pkgNode.GetName())
	require.Equal(t, "1.25.3", pkgNode.GetVersion())
}

const testJSON22Document = `{
  "spdxVersion": "SPDX-2.2",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "json22-test-doc",
  "documentNamespace": "https://sbom.k8s.io/test/json22",
  "creationInfo": {
    "created": "2026-01-01T00:00:00Z",
    "creators": ["Organization: Kubernetes"]
  },
  "packages": [
    {
      "name": "kubectl",
      "SPDXID": "SPDXRef-Package-kubectl",
      "versionInfo": "v1.33.0",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false,
      "licenseConcluded": "Apache-2.0",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION"
    }
  ],
  "documentDescribes": ["SPDXRef-Package-kubectl"]
}`

func TestUnserialize22JSON(t *testing.T) {
	doc, err := tagvalue.NewUnserializer22().Unserialize(strings.NewReader(testJSON22Document), nil, nil)
	require.NoError(t, err)
	require.Equal(t, "json22-test-doc", doc.GetMetadata().GetName())
	require.Len(t, doc.GetNodeList().GetNodes(), 1)

	node := doc.GetNodeList().GetNodes()[0]
	require.Equal(t, "kubectl", node.GetName())
	require.Equal(t, "v1.33.0", node.GetVersion())
	require.Equal(t, "Apache-2.0", node.GetLicenseConcluded())
	require.Contains(t, doc.GetNodeList().GetRootElements(), node.GetId())
}

// TestUnserialize22TVLegacy parses an SPDX 2.2 tag-value document
// rendered by bom's current template renderer: old Kubernetes release
// SBOMs (up to 1.23) declare SPDX-2.2.
func TestUnserialize22TVLegacy(t *testing.T) {
	ldoc := bomspdx.NewDocument()
	ldoc.Version = "SPDX-2.2"
	ldoc.Name = "legacy-22-doc"
	ldoc.Namespace = "https://sbom.k8s.io/test/legacy22"

	pkg := bomspdx.NewPackage()
	pkg.SetSPDXID("SPDXRef-Package-kubectl")
	pkg.Name = "kubectl"
	pkg.Version = "v1.23.0"
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
	require.Contains(t, tv, "SPDXVersion: SPDX-2.2\n")

	pbom, err := tagvalue.NewUnserializer22TV().Unserialize(strings.NewReader(tv), nil, nil)
	require.NoError(t, err)
	require.Equal(t, "legacy-22-doc", pbom.GetMetadata().GetName())

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
	require.NotNil(t, fileNode, "kubectl file node not found (package files not hoisted)")
	require.Equal(t, "v1.23.0", pkgNode.GetVersion())
	require.Equal(t, sbom.Node_FILE, fileNode.GetType())
}

// TestRegister22 exercises the 2.2 formats through protobom's public
// writer entry point.
func TestRegister22(t *testing.T) {
	tagvalue.Register()

	var buf bytes.Buffer
	w := writer.New(writer.WithFormat(formats.SPDX22TV))
	require.NoError(t, w.WriteStream(testDocument(t), &buf))
	require.Contains(t, buf.String(), "SPDXVersion: SPDX-2.2\n")
	require.Contains(t, buf.String(), "PackageName: nginx\n")

	buf.Reset()
	w = writer.New(writer.WithFormat(formats.SPDX22JSON))
	require.NoError(t, w.WriteStream(testDocument(t), &buf))
	require.Contains(t, buf.String(), `"spdxVersion"`)
	require.Contains(t, buf.String(), "SPDX-2.2")
}

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

package convert_test

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"sigs.k8s.io/bom/internal/convert"
	"sigs.k8s.io/bom/pkg/spdx"
)

// legacyDocument builds a legacy document with one root package
// containing a file, exercising the field mappings.
func legacyDocument(t *testing.T) *spdx.Document {
	t.Helper()
	doc := spdx.NewDocument()
	doc.Name = "legacy-doc"
	doc.Namespace = "https://sbom.k8s.io/test/legacy"
	doc.Created = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	doc.Creator.Person = "Jane Doe (jane@example.com)"
	doc.Creator.Organization = "Kubernetes Release Engineering"
	doc.Creator.Tool = []string{"bom-v1.0.0"}

	pkg := spdx.NewPackage()
	pkg.SetSPDXID("SPDXRef-Package-kubectl")
	pkg.Name = "kubectl"
	pkg.Version = "v1.33.0"
	pkg.LicenseConcluded = "Apache-2.0"
	pkg.LicenseDeclared = "NOASSERTION"
	pkg.PrimaryPurpose = "APPLICATION"
	pkg.Supplier.Person = "Kubernetes Release Managers (release-managers@kubernetes.io)"
	pkg.Checksum = map[string]string{
		"SHA256": "9f7fd60e5346e9b6b9e6dbc769ffca94a394a5253bb45a2cbca4fbe3f4d34a0f",
	}
	pkg.ExternalRefs = []spdx.ExternalRef{
		{Category: "PACKAGE-MANAGER", Type: "purl", Locator: "pkg:golang/k8s.io/kubectl@v1.33.0"},
		{Category: "PACKAGE-MANAGER", Type: "npm", Locator: "https://npmjs.com/kubectl"},
	}

	file := spdx.NewFile()
	file.SetSPDXID("SPDXRef-File-kubectl-bin")
	file.Name = "bin/kubectl"
	file.LicenseInfoInFile = "Apache-2.0"
	file.Checksum = map[string]string{
		"SHA1": "f572d396fae9206628714fb2ce00f72e94f2258f",
	}
	require.NoError(t, pkg.AddFile(file))
	require.NoError(t, doc.AddPackage(pkg))
	return doc
}

func TestFromSPDXMetadata(t *testing.T) {
	pdoc, err := convert.FromSPDX(legacyDocument(t))
	require.NoError(t, err)

	md := pdoc.GetMetadata()
	require.Equal(t, "legacy-doc", md.GetName())
	require.Equal(t, "https://sbom.k8s.io/test/legacy#SPDXRef-DOCUMENT", md.GetId())
	require.Equal(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), md.GetDate().AsTime())

	require.Len(t, md.GetAuthors(), 2)
	require.Equal(t, "Jane Doe", md.GetAuthors()[0].GetName())
	require.Equal(t, "jane@example.com", md.GetAuthors()[0].GetEmail())
	require.False(t, md.GetAuthors()[0].GetIsOrg())
	require.Equal(t, "Kubernetes Release Engineering", md.GetAuthors()[1].GetName())
	require.True(t, md.GetAuthors()[1].GetIsOrg())

	require.Len(t, md.GetTools(), 1)
	require.Equal(t, "bom-v1.0.0", md.GetTools()[0].GetName())
}

func TestFromSPDXGraph(t *testing.T) {
	pdoc, err := convert.FromSPDX(legacyDocument(t))
	require.NoError(t, err)

	nl := pdoc.GetNodeList()
	require.Equal(t, []string{"Package-kubectl"}, nl.GetRootElements())
	require.Len(t, nl.GetNodes(), 2)

	pkgNode := nl.GetNodeByID("Package-kubectl")
	require.NotNil(t, pkgNode)
	require.Equal(t, sbom.Node_PACKAGE, pkgNode.GetType())
	require.Equal(t, "kubectl", pkgNode.GetName())
	require.Equal(t, "v1.33.0", pkgNode.GetVersion())
	require.Equal(t, "Apache-2.0", pkgNode.GetLicenseConcluded())
	require.Empty(t, pkgNode.GetLicenses(), "NOASSERTION declared license must be dropped")
	require.Equal(t, []sbom.Purpose{sbom.Purpose_APPLICATION}, pkgNode.GetPrimaryPurpose())
	require.Equal(t,
		map[int32]string{int32(sbom.HashAlgorithm_SHA256): "9f7fd60e5346e9b6b9e6dbc769ffca94a394a5253bb45a2cbca4fbe3f4d34a0f"},
		pkgNode.GetHashes(),
	)
	require.Equal(t,
		map[int32]string{int32(sbom.SoftwareIdentifierType_PURL): "pkg:golang/k8s.io/kubectl@v1.33.0"},
		pkgNode.GetIdentifiers(),
	)
	require.Len(t, pkgNode.GetExternalReferences(), 1)
	require.Equal(t, sbom.ExternalReference_NPM, pkgNode.GetExternalReferences()[0].GetType())
	require.Equal(t, "https://npmjs.com/kubectl", pkgNode.GetExternalReferences()[0].GetUrl())
	require.Len(t, pkgNode.GetSuppliers(), 1)
	require.Equal(t, "Kubernetes Release Managers", pkgNode.GetSuppliers()[0].GetName())
	require.Equal(t, "release-managers@kubernetes.io", pkgNode.GetSuppliers()[0].GetEmail())

	fileNode := nl.GetNodeByID("File-kubectl-bin")
	require.NotNil(t, fileNode)
	require.Equal(t, sbom.Node_FILE, fileNode.GetType())
	require.Equal(t, "bin/kubectl", fileNode.GetName())
	require.Equal(t, []string{"Apache-2.0"}, fileNode.GetLicenses())

	require.Len(t, nl.GetEdges(), 1)
	edge := nl.GetEdges()[0]
	require.Equal(t, sbom.Edge_contains, edge.GetType())
	require.Equal(t, "Package-kubectl", edge.GetFrom())
	require.Equal(t, []string{"File-kubectl-bin"}, edge.GetTo())
}

func TestFromSPDXNilGuard(t *testing.T) {
	_, err := convert.FromSPDX(nil)
	require.Error(t, err)
}

// TestConverterClosure round-trips a protobom document through the
// legacy model twice: after the first pass normalizes the data, the
// second must reproduce it exactly.
func TestConverterClosure(t *testing.T) {
	l1, err := convert.ToSPDX(testDocument(t))
	require.NoError(t, err)
	pb1, err := convert.FromSPDX(l1)
	require.NoError(t, err)

	l2, err := convert.ToSPDX(pb1)
	require.NoError(t, err)
	pb2, err := convert.FromSPDX(l2)
	require.NoError(t, err)

	require.True(t, pb1.GetNodeList().Equal(pb2.GetNodeList()), "node lists differ after round trip")
	require.True(t, proto.Equal(pb1.GetMetadata(), pb2.GetMetadata()), "metadata differs after round trip")
}

// TestConverterGoldenClosure round-trips the golden documents that
// snapshot bom's current generation output. The documents parsed by
// the legacy parser must survive protobom → legacy → protobom
// conversion unchanged.
func TestConverterGoldenClosure(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "test", "golden", "testdata", "golden", "*.spdx*"))
	require.NoError(t, err)
	require.NotEmpty(t, paths, "no golden fixtures found")

	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			ldoc, err := spdx.OpenDoc(path)
			if err != nil && strings.Contains(err.Error(), "duplicate SPDXID") &&
				strings.Contains(err.Error(), "«UUID»") {
				// The golden scrub collapses the random UUID suffixes
				// into a single placeholder to keep the fixtures
				// deterministic; in this fixture that collides two
				// generated IDs and the tag-value parser rejects the
				// document before conversion is involved.
				t.Skipf("fixture not parseable after golden scrubbing: %v", err)
			}
			require.NoError(t, err)

			pb1, err := convert.FromSPDX(ldoc)
			require.NoError(t, err)
			require.NotEmpty(t, pb1.GetNodeList().GetNodes())

			l2, err := convert.ToSPDX(pb1)
			require.NoError(t, err)
			pb2, err := convert.FromSPDX(l2)
			require.NoError(t, err)

			require.True(t, pb1.GetNodeList().Equal(pb2.GetNodeList()), "node lists differ after round trip")
			require.True(t, proto.Equal(pb1.GetMetadata(), pb2.GetMetadata()), "metadata differs after round trip")
		})
	}
}

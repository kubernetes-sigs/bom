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

package golden

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/protobom/protobom/pkg/reader"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/bom/pkg/spdx"
)

// spdx3Element is the subset of the SPDX 3 JSON-LD element properties
// the test looks at.
type spdx3Element struct {
	Type             string   `json:"type"`
	SpdxID           string   `json:"spdxId"`
	Name             string   `json:"name"`
	CreatedBy        []string `json:"createdBy"`
	RootElement      []string `json:"rootElement"`
	SbomType         []string `json:"software_sbomType"`
	PackageURL       string   `json:"software_packageUrl"`
	PackageVersion   string   `json:"software_packageVersion"`
	PrimaryPurpose   string   `json:"software_primaryPurpose"`
	From             string   `json:"from"`
	To               []string `json:"to"`
	RelationshipType string   `json:"relationshipType"`
	Expression       string   `json:"simplelicensing_licenseExpression"`
}

// TestSPDX3Output checks the structure of the SPDX 3 documents bom
// writes. The output is parsed and checked element by element; a
// byte-level golden file can follow now that protobom v0.6.2 writes
// hashes and identifiers deterministically (protobom/protobom#480).
func TestSPDX3Output(t *testing.T) {
	pdoc, err := spdx.NewDocBuilder().GenerateProtobom(&spdx.DocGenerateOptions{
		Name:       "bom-golden-spdx3",
		Namespace:  "https://sbom.k8s.io/golden/spdx3",
		Tarballs:   []string{buildImageArchive(t)},
		Files:      []string{filepath.Join("testdata", "files", "hello.txt")},
		ScanImages: true,
	})
	require.NoError(t, err)

	// A declared license list mixing an expression with other entries,
	// which has to keep its meaning when joined into one expression.
	var baseFiles *sbom.Node
	for _, node := range pdoc.GetNodeList().GetNodes() {
		if node.GetName() == "base-files" {
			baseFiles = node
		}
	}
	require.NotNil(t, baseFiles)
	baseFiles.Licenses = append(baseFiles.Licenses, "MIT or Apache-2.0")
	ldoc, err := spdx.FromProtobom(pdoc)
	require.NoError(t, err)

	var out bytes.Buffer
	require.NoError(t, spdx.WriteSPDX3(&out, pdoc))
	var envelope struct {
		Graph []spdx3Element `json:"@graph"`
	}
	require.NoError(t, json.Unmarshal(out.Bytes(), &envelope))

	byID := map[string]spdx3Element{}
	byType := map[string][]spdx3Element{}
	for _, el := range envelope.Graph {
		if el.SpdxID != "" {
			byID[el.SpdxID] = el
		}
		byType[el.Type] = append(byType[el.Type], el)
	}
	ns := "https://sbom.k8s.io/golden/spdx3"

	// The document, who made it and what it describes.
	require.Len(t, byType["SpdxDocument"], 1)
	require.Equal(t, ns, byType["SpdxDocument"][0].SpdxID)
	require.Equal(t, "bom-golden-spdx3", byType["SpdxDocument"][0].Name)
	require.Len(t, byType["CreationInfo"], 1)
	require.Len(t, byType["CreationInfo"][0].CreatedBy, 1)
	creator := byID[byType["CreationInfo"][0].CreatedBy[0]]
	require.Equal(t, "Organization", creator.Type)
	require.Equal(t, "Kubernetes Release Engineering", creator.Name)
	require.Len(t, byType["software_Sbom"], 1)
	require.Equal(t, []string{"analyzed"}, byType["software_Sbom"][0].SbomType)
	roots := make([]string, 0, len(pdoc.GetNodeList().GetRootElements()))
	for _, id := range pdoc.GetNodeList().GetRootElements() {
		roots = append(roots, ns+"#"+id)
	}
	require.ElementsMatch(t, roots, byType["software_Sbom"][0].RootElement)

	// Every node is an element, packages carry their version and purl.
	require.Len(t, append(byType["software_Package"], byType["software_File"]...), len(pdoc.GetNodeList().GetNodes()))
	pkg := byID[ns+"#"+baseFiles.GetId()]
	require.Equal(t, "software_Package", pkg.Type)
	require.Equal(t, "12.4+deb12u5", pkg.PackageVersion)
	require.Equal(t, "pkg:deb/debian/base-files@12.4%2Bdeb12u5?arch=amd64&distro=debian-12", pkg.PackageURL)

	// Files have the purpose their type suggests.
	require.Len(t, byType["software_File"], 1)
	require.Equal(t, "documentation", byType["software_File"][0].PrimaryPurpose)

	// Licenses are stated with relationships to one expression each,
	// the same expression the SPDX 2.3 output declares.
	declared := map[string]string{}
	concluded := map[string]string{}
	for _, rel := range byType["Relationship"] {
		switch rel.RelationshipType {
		case "hasDeclaredLicense":
			require.Len(t, rel.To, 1)
			declared[rel.From] = licenseExpression(byID, rel.To[0])
		case "hasConcludedLicense":
			require.Len(t, rel.To, 1)
			concluded[rel.From] = licenseExpression(byID, rel.To[0])
		}
	}
	require.Equal(t,
		"GPL-2.0-or-later AND LicenseRef-GPL-3-or-later-with-Autoconf-data-exception AND LicenseRef-public-domain AND (MIT OR Apache-2.0)",
		declared[pkg.SpdxID],
	)
	require.Equal(t, "GPL-2.0-or-later", concluded[pkg.SpdxID])
	lpkgs := legacyPackages(ldoc)
	require.Len(t, lpkgs, len(byType["software_Package"]))
	for id, lpkg := range lpkgs {
		el := ns + "#" + strings.TrimPrefix(id, "SPDXRef-")
		expected := lpkg.LicenseDeclared
		if expected == spdx.NOASSERTION {
			// Nothing asserted: no license, or the NoAssertionLicense
			// individual.
			require.Contains(t, []string{"", spdx.NOASSERTION}, declared[el], "declared license of %s", id)
			continue
		}
		require.Equal(t, expected, declared[el], "declared license of %s", id)
	}
	for _, expr := range concluded {
		require.NotEqual(t, spdx.NOASSERTION, expr)
	}

	// protobom reads the document back into the same graph, its
	// element identifiers resolved against the namespace.
	rt, err := reader.New().ParseStream(bytes.NewReader(out.Bytes()))
	require.NoError(t, err)
	require.Len(t, rt.GetNodeList().GetNodes(), len(pdoc.GetNodeList().GetNodes()))
	require.Equal(t, edgeTargets(pdoc), edgeTargets(rt))
	require.ElementsMatch(t, roots, rt.GetNodeList().GetRootElements())
}

// licenseIndividuals are the IRIs of the SPDX 3 individuals standing
// for no license and for no assertion, which a serializer may refer to
// instead of writing a license expression element.
var licenseIndividuals = map[string]string{
	"https://spdx.org/rdf/3.0.1/terms/ExpandedLicensing/NoneLicense":        spdx.NONE,
	"https://spdx.org/rdf/3.0.1/terms/ExpandedLicensing/NoAssertionLicense": spdx.NOASSERTION,
	"https://spdx.org/rdf/3.0.1/terms/Licensing/None":                       spdx.NONE,
	"https://spdx.org/rdf/3.0.1/terms/Licensing/NoAssertion":                spdx.NOASSERTION,
}

// licenseExpression returns the license expression a license
// relationship points to, either an element of the document or one of
// the individuals for NONE and NOASSERTION.
func licenseExpression(byID map[string]spdx3Element, id string) string {
	if expr, ok := licenseIndividuals[id]; ok {
		return expr
	}
	return byID[id].Expression
}

// legacyPackages returns every package of a legacy document by
// identifier, including those only reachable through relationships.
func legacyPackages(doc *spdx.Document) map[string]*spdx.Package {
	pkgs := map[string]*spdx.Package{}
	seen := map[string]bool{}
	var visit func(obj spdx.Object)
	visit = func(obj spdx.Object) {
		if seen[obj.SPDXID()] {
			return
		}
		seen[obj.SPDXID()] = true
		if pkg, ok := obj.(*spdx.Package); ok {
			pkgs[pkg.SPDXID()] = pkg
		}
		for _, rel := range *obj.GetRelationships() {
			if rel.Peer != nil {
				visit(rel.Peer)
			}
		}
	}
	for _, pkg := range doc.Packages {
		visit(pkg)
	}
	for _, file := range doc.Files {
		visit(file)
	}
	return pkgs
}

// edgeTargets counts the relationships of a document by type.
func edgeTargets(doc *sbom.Document) map[sbom.Edge_Type]int {
	counts := map[sbom.Edge_Type]int{}
	for _, edge := range doc.GetNodeList().GetEdges() {
		counts[edge.GetType()] += len(edge.GetTo())
	}
	return counts
}

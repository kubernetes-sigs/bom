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

package dot_test

import (
	"strings"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/bom/internal/dot"
	"sigs.k8s.io/bom/internal/sbomio"
)

// diamondDocument builds the graph from the feature request: two
// top-level packages both containing python, which contains sqlite.
func diamondDocument() *sbom.Document {
	doc := sbom.NewDocument()
	doc.Metadata.Name = "Document"
	nl := doc.GetNodeList()
	nl.AddRootNode(&sbom.Node{Id: "glib", Type: sbom.Node_PACKAGE, Name: "glib"})
	nl.AddRootNode(&sbom.Node{Id: "gnome", Type: sbom.Node_PACKAGE, Name: "gnome"})
	nl.AddNode(&sbom.Node{
		Id: "python", Type: sbom.Node_PACKAGE, Name: "python", Version: "3.12",
		LicenseConcluded: "PSF-2.0",
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): "pkg:generic/python@3.12",
		},
	})
	nl.AddNode(&sbom.Node{Id: "sqlite", Type: sbom.Node_PACKAGE, Name: "sqlite"})
	nl.AddEdge(&sbom.Edge{Type: sbom.Edge_contains, From: "glib", To: []string{"python"}})
	nl.AddEdge(&sbom.Edge{Type: sbom.Edge_contains, From: "gnome", To: []string{"python"}})
	nl.AddEdge(&sbom.Edge{Type: sbom.Edge_contains, From: "python", To: []string{"sqlite"}})
	return doc
}

func render(t *testing.T, doc *sbom.Document, opts *dot.Options) string {
	t.Helper()
	var sb strings.Builder
	require.NoError(t, dot.Write(&sb, doc, opts))
	return sb.String()
}

const preamble = `  rankdir=LR;
  node [shape=box fontname="monospace"];
  edge [fontname="monospace" fontsize=10];
`

func TestWrite(t *testing.T) {
	t.Parallel()
	require.Equal(t, `digraph "Document" {
`+preamble+`  "DOCUMENT" [label="Document" shape=folder];
  "glib" [label="glib" tooltip="glib"];
  "gnome" [label="gnome" tooltip="gnome"];
  "python" [label="python@3.12" tooltip="python\npkg:generic/python@3.12\nLicense: PSF-2.0"];
  "sqlite" [label="sqlite" tooltip="sqlite"];
  "DOCUMENT" -> "glib" [label="DESCRIBES"];
  "DOCUMENT" -> "gnome" [label="DESCRIBES"];
  "glib" -> "python" [label="CONTAINS"];
  "gnome" -> "python" [label="CONTAINS"];
  "python" -> "sqlite" [label="CONTAINS"];
}
`, render(t, diamondDocument(), nil))
}

func TestWriteDepth(t *testing.T) {
	t.Parallel()
	out := render(t, diamondDocument(), &dot.Options{Depth: 1})
	require.Contains(t, out, `"glib" [`)
	require.Contains(t, out, `"gnome" [`)
	require.NotContains(t, out, `"python"`)

	out = render(t, diamondDocument(), &dot.Options{Depth: 2})
	require.Contains(t, out, `"gnome" -> "python"`)
	require.NotContains(t, out, `"sqlite"`)
}

func TestWriteRoot(t *testing.T) {
	t.Parallel()
	// SPDX identifiers are accepted with their prefix.
	require.Equal(t, `digraph "Document" {
`+preamble+`  "gnome" [label="gnome" tooltip="gnome"];
  "python" [label="python@3.12" tooltip="python\npkg:generic/python@3.12\nLicense: PSF-2.0"];
  "gnome" -> "python" [label="CONTAINS"];
}
`, render(t, diamondDocument(), &dot.Options{Root: "SPDXRef-gnome", Depth: 1}))

	out := render(t, diamondDocument(), &dot.Options{Root: "gnome"})
	require.Contains(t, out, `"python" -> "sqlite"`)
	require.NotContains(t, out, `"glib"`)

	err := dot.Write(&strings.Builder{}, diamondDocument(), &dot.Options{Root: "nope"})
	require.ErrorContains(t, err, `element "nope" not found`)
}

func TestWritePurls(t *testing.T) {
	t.Parallel()
	out := render(t, diamondDocument(), &dot.Options{Purls: true})
	require.Contains(t, out, `"python" [label="pkg:generic/python@3.12"`)
	require.Contains(t, out, `"sqlite" [label="sqlite"`)
}

func TestWriteGraphShape(t *testing.T) {
	t.Parallel()
	doc := sbom.NewDocument()
	nl := doc.GetNodeList()
	nl.AddRootNode(&sbom.Node{Id: "pkg", Type: sbom.Node_PACKAGE, Name: `we"ird\name`})
	nl.AddNode(&sbom.Node{Id: "file", Type: sbom.Node_FILE, Name: "main.go", Version: "1"})
	nl.AddNode(&sbom.Node{Id: "orphan", Type: sbom.Node_PACKAGE})
	nl.AddNode(&sbom.Node{Id: "DOCUMENT", Type: sbom.Node_PACKAGE, Name: "clash"})
	nl.AddEdge(&sbom.Edge{Type: sbom.Edge_contains, From: "pkg", To: []string{"file", "file", "elsewhere"}})
	nl.AddEdge(&sbom.Edge{Type: sbom.Edge_dependsOn, From: "pkg", To: []string{"file"}})
	nl.AddEdge(&sbom.Edge{Type: sbom.Edge_runtimeDependency, From: "orphan", To: []string{"DOCUMENT"}})
	nl.AddEdge(&sbom.Edge{Type: sbom.Edge_contains, From: "elsewhere", To: []string{"pkg"}})

	// Relationships between the same pair share an edge, the document
	// node dodges the element named like it, and only the declared
	// root is described by the document.
	require.Equal(t, `digraph "SBOM" {
`+preamble+`  "_DOCUMENT" [label="SBOM" shape=folder];
  "pkg" [label="we\"ird\\name" tooltip="pkg"];
  "file" [label="main.go" shape=note tooltip="file"];
  "orphan" [label="orphan" tooltip="orphan"];
  "DOCUMENT" [label="clash" tooltip="DOCUMENT"];
  "_DOCUMENT" -> "pkg" [label="DESCRIBES"];
  "pkg" -> "file" [label="CONTAINS, DEPENDS_ON"];
  "orphan" -> "DOCUMENT" [label="RUNTIME_DEPENDENCY_OF"];
}
`, render(t, doc, nil))

	out := render(t, doc, &dot.Options{NoFiles: true})
	require.NotContains(t, out, `"file"`)
	require.Contains(t, out, `"pkg" [`)
}

func TestWriteCycles(t *testing.T) {
	t.Parallel()
	// No element is declared at the top level and every element has a
	// relationship pointing at it, as when a tool records both
	// directions of each relationship.
	doc := sbom.NewDocument()
	nl := doc.GetNodeList()
	nl.AddNode(&sbom.Node{Id: "a", Type: sbom.Node_PACKAGE, Name: "a"})
	nl.AddNode(&sbom.Node{Id: "b", Type: sbom.Node_PACKAGE, Name: "b"})
	nl.AddNode(&sbom.Node{Id: "c", Type: sbom.Node_PACKAGE, Name: "c"})
	nl.AddEdge(&sbom.Edge{Type: sbom.Edge_contains, From: "a", To: []string{"b"}})
	nl.AddEdge(&sbom.Edge{Type: sbom.Edge_contained_by, From: "b", To: []string{"a"}})
	nl.AddEdge(&sbom.Edge{Type: sbom.Edge_dependsOn, From: "c", To: []string{"c"}})

	require.Equal(t, `digraph "SBOM" {
`+preamble+`  "DOCUMENT" [label="SBOM" shape=folder];
  "a" [label="a" tooltip="a"];
  "b" [label="b" tooltip="b"];
  "c" [label="c" tooltip="c"];
  "a" -> "b" [label="CONTAINS"];
  "b" -> "a" [label="CONTAINED_BY"];
  "c" -> "c" [label="DEPENDS_ON"];
}
`, render(t, doc, nil))

	// A cycle that leads to another element is entered at the cycle,
	// even when that element comes first in the document.
	doc2 := sbom.NewDocument()
	nl2 := doc2.GetNodeList()
	nl2.AddNode(&sbom.Node{Id: "tail", Type: sbom.Node_PACKAGE, Name: "tail"})
	nl2.AddNode(&sbom.Node{Id: "a", Type: sbom.Node_PACKAGE, Name: "a"})
	nl2.AddNode(&sbom.Node{Id: "b", Type: sbom.Node_PACKAGE, Name: "b"})
	nl2.AddEdge(&sbom.Edge{Type: sbom.Edge_contains, From: "a", To: []string{"b"}})
	nl2.AddEdge(&sbom.Edge{Type: sbom.Edge_contains, From: "b", To: []string{"a", "tail"}})
	out2 := render(t, doc2, &dot.Options{Depth: 1})
	require.Contains(t, out2, `"a" [`)
	require.NotContains(t, out2, `"tail"`)

	// Walking a cycle from a root ends.
	out := render(t, doc, &dot.Options{Root: "b", Depth: 5})
	require.Contains(t, out, `"a" -> "b"`)
	require.Contains(t, out, `"b" -> "a"`)
}

func TestWriteEmpty(t *testing.T) {
	t.Parallel()
	require.Equal(t, `digraph "SBOM" {
`+preamble+`  "DOCUMENT" [label="SBOM" shape=folder];
}
`, render(t, nil, nil))
}

func TestWriteSPDX(t *testing.T) {
	t.Parallel()
	doc, err := sbomio.Open("../../pkg/spdx/testdata/nginx.spdx")
	require.NoError(t, err)
	out := render(t, doc, &dot.Options{Depth: 1})
	require.Contains(t, out, `"DOCUMENT" -> "Package-nginx" [label="DESCRIBES"];`)
	require.NotContains(t, out, "CONTAINS")

	out = render(t, doc, &dot.Options{Root: "SPDXRef-Package-nginx", Depth: 1})
	require.Contains(t, out, `"Package-nginx" -> `)
}

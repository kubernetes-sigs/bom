/*
Copyright 2022 The Kubernetes Authors.

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

package query

import (
	"fmt"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"
)

// testDocument builds a small document: two image packages and two
// files at the top level, with one of the packages containing a file
// one level down.
func testDocument() *sbom.Document {
	nl := &sbom.NodeList{}

	for i, s := range []string{"packageOne", "packageTwo"} {
		dg := "sha256:4ed64c2e0857ad21c38b98345ebb5edb01791a0a10b0e9e3d9ddde185cdbd31a"
		repo := "index.docker.io%2Flibrary"
		if i == 1 {
			dg = "sha256:c0d8e30ad4f13b5f26794264fe057c488c72a5112978b1c24f3940dfaf69368a"
			repo = "gcr.io%2Fproject"
		}
		nl.AddRootNode(&sbom.Node{
			Id:   s,
			Type: sbom.Node_PACKAGE,
			Name: fmt.Sprintf("gcr.io/puerco-chainguard/images/%s:v9.0.2-buster", s),
			Identifiers: map[int32]string{
				int32(sbom.SoftwareIdentifierType_PURL): fmt.Sprintf(
					"pkg:oci/%s@%s?repository_url=%s&tag=nginx", s, dg, repo,
				),
			},
		})
	}

	for _, s := range []string{"file1.txt", "file2.txt"} {
		nl.AddRootNode(&sbom.Node{
			Id: s, Type: sbom.Node_FILE, Name: s, FileName: s,
		})
	}

	nl.Nodes = append(nl.Nodes, &sbom.Node{
		Id: "subfile1", Type: sbom.Node_FILE,
		Name: "subfile1.txt", FileName: "subfile1.txt",
	})
	nl.Edges = append(nl.Edges, &sbom.Edge{
		Type: sbom.Edge_contains, From: "packageTwo", To: []string{"subfile1"},
	})

	return &sbom.Document{Metadata: &sbom.Metadata{}, NodeList: nl}
}

func testFilterResults() FilterResults {
	return (&defaultEngineImplementation{}).resultsFromDocument(testDocument())
}

func TestDepth(t *testing.T) {
	fr := testFilterResults()
	newResults := fr.Apply(&DepthFilter{TargetDepth: 1})
	require.NotNil(t, newResults)
	require.Len(t, newResults.Objects, 1)
	for id, o := range newResults.Objects {
		require.Equal(t, o.GetId(), id)
		require.Equal(t, "subfile1", id)
	}

	fr2 := testFilterResults()
	// At level 0, we get the top elements in the testset
	fr2.Apply(&DepthFilter{TargetDepth: 0})
	require.NotNil(t, fr2.Objects)
	require.NoError(t, fr2.Error)
	require.Len(t, fr2.Objects, 4)

	// Beyond, we should not find more elements
	fr3 := testFilterResults()
	fr3.Apply(&DepthFilter{TargetDepth: 2})
	require.NotNil(t, fr3.Objects)
	require.NoError(t, fr3.Error)
	require.Empty(t, fr3.Objects)
}

func TestName(t *testing.T) {
	fr := testFilterResults()
	newResults := fr.Apply(&NameFilter{Pattern: "subfile"})
	require.Len(t, newResults.Objects, 1)

	// Match the two image packages
	fr = testFilterResults()
	newResults = fr.Apply(&NameFilter{Pattern: "puerco-chainguard"})
	require.Len(t, newResults.Objects, 2)
}

func TestPurl(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		num     int
		mustErr bool
		descr   string
	}{
		{"pkg:oci/*/*", 2, false, "match by type"},
		{"pkg:oci/*/packageOne", 1, false, "match by name"},
		{"sdlkfjlskdjf", 4, true, "invalid purl"},
		{"pkg:oci/*/*?repository_url=gcr.io%2Fproject", 1, false, "match by qualifiers"},
		{"pkg:oci/*/*?repository_url=index.docker.io%2Flibrary", 1, false, "match by qualifiers2"},
		{"pkg:oci/*/*@sha256:c0d8e30ad4f13b5f26794264fe057c488c72a5112978b1c24f3940dfaf69368a", 1, false, "match by version"},
	} {
		fr := testFilterResults()
		newResults := fr.Apply(&PurlFilter{Pattern: tc.pattern})
		if tc.mustErr {
			require.Error(t, newResults.Error, tc.descr)
		} else {
			require.NoError(t, newResults.Error, tc.descr)
		}
		require.Len(t, newResults.Objects, tc.num, tc.descr)
	}
}

// cycleDocument builds a document whose single root leads nowhere
// while two packages depend on each other: no root reaches the pair,
// and neither is unreferenced.
func cycleDocument() *sbom.Document {
	nl := &sbom.NodeList{}
	nl.AddRootNode(&sbom.Node{Id: "root", Type: sbom.Node_PACKAGE, Name: "root"})
	nl.AddNode(&sbom.Node{Id: "left", Type: sbom.Node_PACKAGE, Name: "left"})
	nl.AddNode(&sbom.Node{Id: "right", Type: sbom.Node_PACKAGE, Name: "right"})
	nl.AddEdge(&sbom.Edge{Type: sbom.Edge_dependsOn, From: "left", To: []string{"right"}})
	nl.AddEdge(&sbom.Edge{Type: sbom.Edge_dependsOn, From: "right", To: []string{"left"}})
	return &sbom.Document{Metadata: &sbom.Metadata{}, NodeList: nl}
}

func TestUnreachableCycle(t *testing.T) {
	results := func() FilterResults {
		return (&defaultEngineImplementation{}).resultsFromDocument(cycleDocument())
	}

	// The first element of the cycle stands in as a top-level element.
	fr := results()
	fr.Apply(&DepthFilter{TargetDepth: 0})
	require.NoError(t, fr.Error)
	require.ElementsMatch(t, []string{"root", "left"}, objectIDs(fr.Objects))

	fr = results()
	fr.Apply(&DepthFilter{TargetDepth: 1})
	require.NoError(t, fr.Error)
	require.ElementsMatch(t, []string{"right"}, objectIDs(fr.Objects))

	for _, name := range []string{"left", "right"} {
		fr = results()
		fr.Apply(&NameFilter{Pattern: "^" + name + "$"})
		require.NoError(t, fr.Error)
		require.ElementsMatch(t, []string{name}, objectIDs(fr.Objects))
	}

	fr = results()
	fr.Apply(&AllFilter{})
	require.NoError(t, fr.Error)
	require.ElementsMatch(t, []string{"root", "left", "right"}, objectIDs(fr.Objects))
}

func TestUnreachableCycleWithTail(t *testing.T) {
	// A cycle that leads to another element is entered at the cycle,
	// even when that element comes first in the document.
	nl := &sbom.NodeList{}
	nl.AddNode(&sbom.Node{Id: "tail", Type: sbom.Node_PACKAGE, Name: "tail"})
	nl.AddNode(&sbom.Node{Id: "a", Type: sbom.Node_PACKAGE, Name: "a"})
	nl.AddNode(&sbom.Node{Id: "b", Type: sbom.Node_PACKAGE, Name: "b"})
	nl.AddEdge(&sbom.Edge{Type: sbom.Edge_contains, From: "a", To: []string{"b"}})
	nl.AddEdge(&sbom.Edge{Type: sbom.Edge_contains, From: "b", To: []string{"a", "tail"}})
	doc := &sbom.Document{Metadata: &sbom.Metadata{}, NodeList: nl}

	fr := (&defaultEngineImplementation{}).resultsFromDocument(doc)
	fr.Apply(&DepthFilter{TargetDepth: 0})
	require.NoError(t, fr.Error)
	require.ElementsMatch(t, []string{"a"}, objectIDs(fr.Objects))
}

func objectIDs(objects map[string]*sbom.Node) []string {
	ids := make([]string, 0, len(objects))
	for id := range objects {
		ids = append(ids, id)
	}
	return ids
}

func TestPurlGolang(t *testing.T) {
	// A module and its dependencies, all top-level so that a match on
	// one does not hide the others from the query.
	nl := &sbom.NodeList{}
	for id, p := range map[string]string{
		"bom":     "pkg:golang/sigs.k8s.io/bom@v0.8.0",
		"cobra":   "pkg:golang/github.com/spf13/cobra@v1.10.1",
		"md2man":  "pkg:golang/github.com/cpuguy83/go-md2man/v2@v2.0.6",
		"yaml":    "pkg:golang/go.yaml.in/yaml/v3@v3.0.4",
		"nons":    "pkg:golang/stdlib@1.25.0",
		"generic": "pkg:generic/github.com/spf13/cobra@v1.10.1",
	} {
		nl.AddRootNode(&sbom.Node{
			Id: id, Type: sbom.Node_PACKAGE, Name: id,
			Identifiers: map[int32]string{int32(sbom.SoftwareIdentifierType_PURL): p},
		})
	}
	doc := &sbom.Document{Metadata: &sbom.Metadata{}, NodeList: nl}

	for _, tc := range []struct {
		pattern string
		expect  []string
	}{
		{"pkg:golang/*", []string{"bom", "cobra", "md2man", "yaml", "nons"}},
		{"pkg:golang/*/*", []string{"bom", "cobra", "md2man", "yaml", "nons"}},
		{"pkg:golang/github.com/*", []string{"cobra", "md2man"}},
		{"pkg:golang/github.com/*/*", []string{"cobra", "md2man"}},
		{"pkg:golang/github.com/spf13/*", []string{"cobra"}},
		{"pkg:golang/github.com/*/cobra", []string{"cobra"}},
		{"pkg:golang/github.com/cpuguy83/go-md2man/v2", []string{"md2man"}},
		{"pkg:golang/github.com/cpuguy83/*", []string{"md2man"}},
		{"pkg:golang/*/v3", []string{"yaml"}},
		{"pkg:golang/go.yaml.in/*@v3.0.4", []string{"yaml"}},
		{"pkg:golang/*.k8s.io/*", []string{"bom"}},
		{"pkg:golang/sigs.k8s.io/bom", []string{"bom"}},
		{"pkg:golang/github.com/spf13", nil},
	} {
		fr := (&defaultEngineImplementation{}).resultsFromDocument(doc)
		fr.Apply(&PurlFilter{Pattern: tc.pattern})
		require.NoError(t, fr.Error, tc.pattern)
		require.ElementsMatch(t, tc.expect, objectIDs(fr.Objects), tc.pattern)
	}
}

func TestPurlLiteralAndSubpath(t *testing.T) {
	nl := &sbom.NodeList{}
	for id, p := range map[string]string{
		"bracket":   "pkg:generic/example/lib%5Bx%5D@1.0",
		"backslash": "pkg:generic/example/back%5Cslash@1.0",
		"subpath":   "pkg:golang/github.com/example/repo@v1.0.0#tools/cmd",
		"plain":     "pkg:golang/github.com/example/repo@v1.0.0",
	} {
		nl.AddRootNode(&sbom.Node{
			Id: id, Type: sbom.Node_PACKAGE, Name: id,
			Identifiers: map[int32]string{int32(sbom.SoftwareIdentifierType_PURL): p},
		})
	}
	doc := &sbom.Document{Metadata: &sbom.Metadata{}, NodeList: nl}

	for _, tc := range []struct {
		pattern string
		expect  []string
	}{
		// Segments that are not patterns match themselves, even when
		// path.Match would reject or reinterpret them.
		{"pkg:generic/example/lib%5Bx%5D", []string{"bracket"}},
		{"pkg:generic/example/back%5Cslash", []string{"backslash"}},
		{"pkg:generic/example/lib*", []string{"bracket"}},
		{"pkg:generic/example/*slash", []string{"backslash"}},
		// A subpath left out matches any.
		{"pkg:golang/github.com/example/repo", []string{"subpath", "plain"}},
		{"pkg:golang/github.com/example/repo#tools/cmd", []string{"subpath"}},
		{"pkg:golang/github.com/example/repo#other", nil},
	} {
		fr := (&defaultEngineImplementation{}).resultsFromDocument(doc)
		fr.Apply(&PurlFilter{Pattern: tc.pattern})
		require.NoError(t, fr.Error, tc.pattern)
		require.ElementsMatch(t, tc.expect, objectIDs(fr.Objects), tc.pattern)
	}
}

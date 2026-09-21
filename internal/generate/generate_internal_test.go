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

package generate

import (
	"testing"
	"time"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"
)

func TestEncodePurls(t *testing.T) {
	purlID := int32(sbom.SoftwareIdentifierType_PURL)
	nl := &sbom.NodeList{Nodes: []*sbom.Node{
		{Id: "pseudo", Identifiers: map[int32]string{purlID: "pkg:golang/sigs.k8s.io/bom@v0.7.1-105+fb96ff42"}},
		{Id: "encoded", Identifiers: map[int32]string{purlID: "pkg:deb/debian/base-files@12.4%2Bdeb12u5?arch=amd64"}},
		{Id: "none"},
	}}
	encodePurls(nl)
	require.Equal(t, "pkg:golang/sigs.k8s.io/bom@v0.7.1-105%2Bfb96ff42", nl.GetNodeByID("pseudo").GetIdentifiers()[purlID])
	require.Equal(t, "pkg:deb/debian/base-files@12.4%2Bdeb12u5?arch=amd64", nl.GetNodeByID("encoded").GetIdentifiers()[purlID])
	require.Empty(t, nl.GetNodeByID("none").GetIdentifiers())
}

func TestCreationTime(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1767225600")
	require.Equal(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), creationTime())

	for _, invalid := range []string{"not a timestamp", "-1", "253402300800", "9223372036854775807"} {
		t.Setenv("SOURCE_DATE_EPOCH", invalid)
		require.WithinDuration(t, time.Now(), creationTime(), time.Minute, invalid)
	}

	t.Setenv("SOURCE_DATE_EPOCH", "")
	require.WithinDuration(t, time.Now(), creationTime(), time.Minute)
}

// sourceNodeList builds the node list of a scanned source: a root
// package containing the given files.
func sourceNodeList(rootID string, fileIDs ...string) *sbom.NodeList {
	nl := &sbom.NodeList{}
	nl.AddRootNode(&sbom.Node{Id: rootID, Type: sbom.Node_PACKAGE})
	for _, id := range fileIDs {
		nl.AddNode(&sbom.Node{Id: id, Type: sbom.Node_FILE})
	}
	if len(fileIDs) > 0 {
		nl.AddEdge(&sbom.Edge{Type: sbom.Edge_contains, From: rootID, To: fileIDs})
	}
	return nl
}

func TestAddSourceNodeList(t *testing.T) {
	// Codebases sharing a name but not a version have distinct roots,
	// while their files are named alike: the files must not merge.
	doc := sbom.NewDocument()
	addSourceNodeList(doc, sourceNodeList("Package-foo-1.0.0", "File-foo-index.js"))
	addSourceNodeList(doc, sourceNodeList("Package-foo-2.0.0", "File-foo-index.js"))
	nl := doc.GetNodeList()
	require.Equal(t, []string{"Package-foo-1.0.0", "Package-foo-2.0.0"}, nl.GetRootElements())
	require.Equal(t, []string{"File-foo-index.js"}, nl.GetEdgeByType("Package-foo-1.0.0", sbom.Edge_contains).GetTo())
	require.Equal(t, []string{"File-foo-index.js-0001"}, nl.GetEdgeByType("Package-foo-2.0.0", sbom.Edge_contains).GetTo())

	// The suffix skips identifiers the source holds itself.
	doc = sbom.NewDocument()
	addSourceNodeList(doc, sourceNodeList("Package-foo", "File-x"))
	addSourceNodeList(doc, sourceNodeList("Package-foo", "File-x", "File-x-0001"))
	nl = doc.GetNodeList()
	require.Equal(t, []string{"Package-foo", "Package-foo-0002"}, nl.GetRootElements())
	require.ElementsMatch(t,
		[]string{"File-x-0002", "File-x-0001"},
		nl.GetEdgeByType("Package-foo-0002", sbom.Edge_contains).GetTo(),
	)
	require.Equal(t, []string{"File-x"}, nl.GetEdgeByType("Package-foo", sbom.Edge_contains).GetTo())
}

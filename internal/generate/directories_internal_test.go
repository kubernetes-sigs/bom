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

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"
)

func TestStripGoDirhashes(t *testing.T) {
	sha256Key := int32(sbom.HashAlgorithm_SHA256)
	goDep := &sbom.Node{
		Id:   "go-dep",
		Type: sbom.Node_PACKAGE,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): "pkg:golang/example.com/dep@v1.0.0",
		},
		Hashes: map[int32]string{
			sha256Key:                      "dirhash-not-a-digest",
			int32(sbom.HashAlgorithm_SHA1): "unrelated",
		},
	}
	otherPkg := &sbom.Node{
		Id:   "npm-dep",
		Type: sbom.Node_PACKAGE,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): "pkg:npm/leftpad@1.0.0",
		},
		Hashes: map[int32]string{sha256Key: "real-digest"},
	}
	file := &sbom.Node{
		Id:     "a-file",
		Type:   sbom.Node_FILE,
		Hashes: map[int32]string{sha256Key: "real-file-digest"},
	}

	nl := &sbom.NodeList{Nodes: []*sbom.Node{goDep, otherPkg, file}}
	stripGoDirhashes(nl)

	require.NotContains(t, goDep.GetHashes(), sha256Key, "go dirhash must be dropped")
	require.Contains(t, goDep.GetHashes(), int32(sbom.HashAlgorithm_SHA1), "other hashes survive")
	require.Equal(t, "real-digest", otherPkg.GetHashes()[sha256Key], "non-go packages keep hashes")
	require.Equal(t, "real-file-digest", file.GetHashes()[sha256Key], "files keep hashes")
}

// Node identifiers shared by the pruning tests.
const (
	rootID   = "root"
	directID = "direct"
)

func TestKeepDirectDependencies(t *testing.T) {
	// root -> direct -> transitive, plus a file the root contains.
	nl := &sbom.NodeList{
		Nodes: []*sbom.Node{
			{Id: rootID, Type: sbom.Node_PACKAGE, Name: rootID},
			{Id: directID, Type: sbom.Node_PACKAGE, Name: directID},
			{Id: "transitive", Type: sbom.Node_PACKAGE, Name: "transitive"},
			{Id: "file", Type: sbom.Node_FILE, Name: "main.go"},
		},
		Edges: []*sbom.Edge{
			{Type: sbom.Edge_dependsOn, From: rootID, To: []string{directID}},
			{Type: sbom.Edge_dependsOn, From: directID, To: []string{"transitive"}},
			{Type: sbom.Edge_contains, From: rootID, To: []string{"file"}},
		},
		RootElements: []string{rootID},
	}

	keepDirectDependencies(nl)

	ids := make([]string, 0, len(nl.GetNodes()))
	for _, node := range nl.GetNodes() {
		ids = append(ids, node.GetId())
	}
	require.ElementsMatch(t, []string{rootID, directID, "file"}, ids,
		"only what the root reaches in one step survives")

	// The edge into the dropped node goes with it.
	for _, edge := range nl.GetEdges() {
		require.NotContains(t, edge.GetTo(), "transitive",
			"edges must not point at a removed node")
	}
}

// TestKeepDirectDependenciesDoesNotCascade pins the subtlety that
// makes this correct: a direct dependency must not act as a root and
// pull in its own dependencies.
func TestKeepDirectDependenciesDoesNotCascade(t *testing.T) {
	nl := &sbom.NodeList{
		Nodes: []*sbom.Node{
			{Id: "a", Type: sbom.Node_PACKAGE},
			{Id: "b", Type: sbom.Node_PACKAGE},
			{Id: "c", Type: sbom.Node_PACKAGE},
			{Id: "d", Type: sbom.Node_PACKAGE},
		},
		Edges: []*sbom.Edge{
			// Ordered so a naive walk would reach c and then d.
			{Type: sbom.Edge_dependsOn, From: "a", To: []string{"b"}},
			{Type: sbom.Edge_dependsOn, From: "b", To: []string{"c"}},
			{Type: sbom.Edge_dependsOn, From: "c", To: []string{"d"}},
		},
		RootElements: []string{"a"},
	}

	keepDirectDependencies(nl)

	ids := make([]string, 0, len(nl.GetNodes()))
	for _, node := range nl.GetNodes() {
		ids = append(ids, node.GetId())
	}
	require.ElementsMatch(t, []string{"a", "b"}, ids)
}

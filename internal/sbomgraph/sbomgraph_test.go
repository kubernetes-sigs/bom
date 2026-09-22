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

package sbomgraph_test

import (
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/bom/internal/sbomgraph"
)

func TestNew(t *testing.T) {
	t.Parallel()

	nl := &sbom.NodeList{}
	nl.AddRootNode(&sbom.Node{Id: "app", Type: sbom.Node_PACKAGE})
	nl.AddNode(&sbom.Node{Id: "lib", Type: sbom.Node_PACKAGE})
	nl.AddNode(&sbom.Node{Id: "file", Type: sbom.Node_FILE})
	nl.AddNode(&sbom.Node{Id: "orphan", Type: sbom.Node_PACKAGE})
	nl.AddNode(&sbom.Node{Id: "left", Type: sbom.Node_PACKAGE})
	nl.AddNode(&sbom.Node{Id: "right", Type: sbom.Node_PACKAGE})
	nl.AddEdge(&sbom.Edge{Type: sbom.Edge_dependsOn, From: "app", To: []string{"lib", "elsewhere"}})
	nl.AddEdge(&sbom.Edge{Type: sbom.Edge_contains, From: "app", To: []string{"lib", "file"}})
	nl.AddEdge(&sbom.Edge{Type: sbom.Edge_dependsOn, From: "app", To: []string{"lib"}})
	nl.AddEdge(&sbom.Edge{Type: sbom.Edge_dependsOn, From: "left", To: []string{"right"}})
	nl.AddEdge(&sbom.Edge{Type: sbom.Edge_dependsOn, From: "right", To: []string{"left"}})

	g := sbomgraph.New(nl, nil)
	require.Equal(t, []string{"app", "lib", "file", "orphan", "left", "right"}, g.IDs())
	require.Equal(t, []string{"app"}, g.Declared())
	// Declared, then unreferenced, then one element per unreached cycle.
	require.Equal(t, []string{"app", "orphan", "left"}, g.Roots())

	// Relationships to elements the document does not define are
	// dropped, and those between the same pair are merged.
	require.Equal(t, []string{"lib", "file"}, g.Next("app"))
	require.Len(t, g.Edges(), 4)
	require.Equal(t, &sbomgraph.Edge{
		From: "app", To: "lib", Types: []sbom.Edge_Type{sbom.Edge_dependsOn, sbom.Edge_contains},
	}, g.Edges()[0])

	id, ok := g.Lookup("SPDXRef-lib")
	require.True(t, ok)
	require.Equal(t, "lib", id)
	_, ok = g.Lookup("elsewhere")
	require.False(t, ok)

	require.Equal(t, map[string]bool{"app": true, "lib": true, "file": true}, g.Reachable([]string{"app"}, 0))
	require.Equal(t, map[string]bool{"app": true}, g.Reachable([]string{"app"}, 1))

	// Filtering out the files drops their relationships too.
	g = sbomgraph.New(nl, func(n *sbom.Node) bool { return n.GetType() != sbom.Node_FILE })
	require.Nil(t, g.Node("file"))
	require.Equal(t, []string{"lib"}, g.Next("app"))
}

func TestCycleRoots(t *testing.T) {
	t.Parallel()

	// A cycle that leads to another element is entered at the cycle,
	// even when that element comes first in the document, and two
	// cycles one leads into get a single root.
	nl := &sbom.NodeList{}
	for _, id := range []string{"tail", "a", "b", "c", "d"} {
		nl.AddNode(&sbom.Node{Id: id, Type: sbom.Node_PACKAGE})
	}
	nl.AddEdge(&sbom.Edge{Type: sbom.Edge_contains, From: "a", To: []string{"b"}})
	nl.AddEdge(&sbom.Edge{Type: sbom.Edge_contains, From: "b", To: []string{"a", "tail", "c"}})
	nl.AddEdge(&sbom.Edge{Type: sbom.Edge_contains, From: "c", To: []string{"d"}})
	nl.AddEdge(&sbom.Edge{Type: sbom.Edge_contains, From: "d", To: []string{"c"}})

	g := sbomgraph.New(nl, nil)
	require.Equal(t, []string{"a"}, g.Roots())
	require.Len(t, g.Reachable(g.Roots(), 0), 5)
}

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

// Package sbomgraph indexes the element graph of a protobom node list
// for traversal. protobom keeps relationships in an edge list separate
// from the nodes, so every consumer walking a document needs the same
// adjacency index and the same notion of which elements are the
// document's top level.
package sbomgraph

import (
	"slices"
	"strings"

	"github.com/protobom/protobom/pkg/sbom"
)

// Edge holds every relationship from one element to another. Types
// lists the relationship types in the order the document first
// declares them, without repetitions.
type Edge struct {
	From, To string
	Types    []sbom.Edge_Type
}

// Graph is the traversal index of a node list. It drops relationships
// pointing at elements the list does not define: protobom expresses a
// relationship to another document that way, and there is nothing to
// follow in this one.
type Graph struct {
	nodes    map[string]*sbom.Node
	order    []string
	edges    []*Edge
	next     map[string][]string
	declared []string
	roots    []string
}

// New indexes a node list. When keep is not nil, only the nodes it
// returns true for, and the relationships between them, are indexed.
func New(nl *sbom.NodeList, keep func(*sbom.Node) bool) *Graph {
	g := &Graph{
		nodes: map[string]*sbom.Node{},
		next:  map[string][]string{},
	}
	for _, node := range nl.GetNodes() {
		id := node.GetId()
		if id == "" || (keep != nil && !keep(node)) {
			continue
		}
		if _, dup := g.nodes[id]; !dup {
			g.order = append(g.order, id)
		}
		g.nodes[id] = node
	}

	// Relationships between the same two elements are merged into one
	// edge, so that a pair related in several ways is walked once.
	byPair := map[[2]string]*Edge{}
	for _, e := range nl.GetEdges() {
		if _, ok := g.nodes[e.GetFrom()]; !ok {
			continue
		}
		for _, to := range e.GetTo() {
			if _, ok := g.nodes[to]; !ok {
				continue
			}
			pair := [2]string{e.GetFrom(), to}
			ed, ok := byPair[pair]
			if !ok {
				ed = &Edge{From: pair[0], To: pair[1]}
				byPair[pair] = ed
				g.edges = append(g.edges, ed)
				g.next[ed.From] = append(g.next[ed.From], to)
			}
			if !slices.Contains(ed.Types, e.GetType()) {
				ed.Types = append(ed.Types, e.GetType())
			}
		}
	}

	for _, id := range nl.GetRootElements() {
		if _, ok := g.nodes[id]; ok && !slices.Contains(g.declared, id) {
			g.declared = append(g.declared, id)
		}
	}

	// Besides the elements the document declares at the top level,
	// every element nothing else points at is a root. Elements still
	// out of reach after that hang off cycles no root leads into; the
	// first element of each such cycle becomes a root too, so that
	// walking from the roots visits every element.
	g.roots = slices.Clone(g.declared)
	referenced := map[string]bool{}
	for _, e := range g.edges {
		referenced[e.To] = true
	}
	for _, id := range g.order {
		if !referenced[id] && !slices.Contains(g.roots, id) {
			g.roots = append(g.roots, id)
		}
	}
	g.roots = append(g.roots, g.cycleRoots(g.Reachable(g.roots, 0))...)
	return g
}

// cycleRoots returns one element for each cycle among the elements
// not in reached that nothing outside the cycle points at, the first
// of the cycle in document order. Every element not in reached is
// reachable from those.
func (g *Graph) cycleRoots(reached map[string]bool) []string {
	// Tarjan's algorithm labels each unreached element with its
	// strongly connected component.
	index := map[string]int{}
	low := map[string]int{}
	component := map[string]int{}
	onStack := map[string]bool{}
	var stack []string
	components := 0
	var visit func(id string)
	visit = func(id string) {
		index[id] = len(index)
		low[id] = index[id]
		stack = append(stack, id)
		onStack[id] = true
		for _, to := range g.next[id] {
			if reached[to] {
				continue
			}
			if _, seen := index[to]; !seen {
				visit(to)
				low[id] = min(low[id], low[to])
			} else if onStack[to] {
				low[id] = min(low[id], index[to])
			}
		}
		if low[id] != index[id] {
			return
		}
		for {
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			onStack[top] = false
			component[top] = components
			if top == id {
				break
			}
		}
		components++
	}
	for _, id := range g.order {
		if _, seen := index[id]; !seen && !reached[id] {
			visit(id)
		}
	}

	entered := map[int]bool{}
	for _, e := range g.edges {
		if reached[e.From] || reached[e.To] {
			continue
		}
		if component[e.From] != component[e.To] {
			entered[component[e.To]] = true
		}
	}
	var roots []string
	picked := map[int]bool{}
	for _, id := range g.order {
		c, ok := component[id]
		if !ok || entered[c] || picked[c] {
			continue
		}
		picked[c] = true
		roots = append(roots, id)
	}
	return roots
}

// Node returns the element with the given id, nil when the graph does
// not hold it.
func (g *Graph) Node(id string) *sbom.Node {
	return g.nodes[id]
}

// IDs returns the ids of the indexed elements in document order.
func (g *Graph) IDs() []string {
	return g.order
}

// Edges returns the relationships between indexed elements, one per
// related pair, in document order.
func (g *Graph) Edges() []*Edge {
	return g.edges
}

// Next returns the ids of the elements id relates to directly.
func (g *Graph) Next(id string) []string {
	return g.next[id]
}

// Declared returns the ids of the elements the document declares at
// its top level.
func (g *Graph) Declared() []string {
	return g.declared
}

// Roots returns the ids of the elements traversal starts from: the
// declared ones, then those no relationship reaches, then one element
// of each cycle no other root leads into.
func (g *Graph) Roots() []string {
	return g.roots
}

// Lookup resolves an element id as given or, failing that, with the
// SPDXRef- prefix protobom strips from SPDX identifiers removed.
func (g *Graph) Lookup(id string) (string, bool) {
	for _, candidate := range []string{id, strings.TrimPrefix(id, "SPDXRef-")} {
		if _, ok := g.nodes[candidate]; ok {
			return candidate, true
		}
	}
	return "", false
}

// Reachable returns the elements within depth levels of starts, starts
// being the first level. A depth of zero or less is unlimited.
func (g *Graph) Reachable(starts []string, depth int) map[string]bool {
	seen := map[string]bool{}
	g.walk(seen, starts, depth)
	return seen
}

// walk adds the elements within depth levels of starts to seen,
// without expanding those already in it.
func (g *Graph) walk(seen map[string]bool, starts []string, depth int) {
	var frontier []string
	for _, id := range starts {
		if !seen[id] {
			seen[id] = true
			frontier = append(frontier, id)
		}
	}
	for step := 1; len(frontier) > 0 && (depth <= 0 || step < depth); step++ {
		var nextFrontier []string
		for _, id := range frontier {
			for _, to := range g.next[id] {
				if !seen[to] {
					seen[to] = true
					nextFrontier = append(nextFrontier, to)
				}
			}
		}
		frontier = nextFrontier
	}
}

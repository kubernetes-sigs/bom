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

// Package dot renders the element graph of a protobom document in the
// Graphviz DOT language (https://graphviz.org/doc/info/lang.html).
// Unlike a tree outline, the rendering keeps each element once, so an
// element reached from several others shows up as a single node with
// several incoming edges.
package dot

import (
	"bufio"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/protobom/protobom/pkg/sbom"

	"sigs.k8s.io/bom/pkg/spdx"
)

// Options control what part of the graph is rendered and how nodes
// are labelled.
type Options struct {
	// Root is the id of the element to render the graph from. SPDX
	// identifiers are accepted with or without their SPDXRef- prefix.
	// Left empty, the graph is rendered from the document.
	Root string

	// Depth limits how many relationship steps are followed from the
	// starting point: from the document, 1 renders its top-level
	// elements only; from Root, 1 renders Root and the elements it
	// relates to directly. Zero or less renders the whole graph.
	Depth int

	// Purls labels packages with their package URL, when they have
	// one, instead of name@version.
	Purls bool

	// NoFiles leaves file elements, and the relationships to and
	// from them, out of the graph.
	NoFiles bool
}

// Write renders the document graph to w.
func Write(w io.Writer, doc *sbom.Document, opts *Options) error {
	if opts == nil {
		opts = &Options{}
	}
	g := newGraph(doc.GetNodeList(), opts.NoFiles)

	// The document stands one step above its top-level elements, so
	// starting from them takes one step off the depth.
	starts, levels := g.roots, opts.Depth
	fromDocument := opts.Root == ""
	if !fromDocument {
		root, ok := g.lookup(opts.Root)
		if !ok {
			return fmt.Errorf("element %q not found in document", opts.Root)
		}
		starts = []string{root}
		if levels > 0 {
			levels++
		}
	}
	visible := g.reachable(starts, levels)

	name := doc.GetMetadata().GetName()
	if name == "" {
		name = "SBOM"
	}
	bw := bufio.NewWriter(w)
	fmt.Fprintf(bw, "digraph %s {\n", quote(name))
	fmt.Fprintln(bw, "  rankdir=LR;")
	fmt.Fprintln(bw, `  node [shape=box fontname="monospace"];`)
	fmt.Fprintln(bw, `  edge [fontname="monospace" fontsize=10];`)
	docID := g.documentID()
	if fromDocument {
		fmt.Fprintf(bw, "  %s [label=%s shape=folder];\n", quote(docID), quote(name))
	}
	for _, id := range g.order {
		if visible[id] {
			writeNode(bw, g.nodes[id], opts)
		}
	}
	if fromDocument {
		for _, id := range g.declared {
			if visible[id] {
				fmt.Fprintf(bw, "  %s -> %s [label=%s];\n", quote(docID), quote(id), quote(string(spdx.DESCRIBES)))
			}
		}
	}
	for _, e := range g.edges {
		if visible[e.from] && visible[e.to] {
			fmt.Fprintf(bw, "  %s -> %s [label=%s];\n", quote(e.from), quote(e.to), quote(strings.Join(e.labels, ", ")))
		}
	}
	fmt.Fprintln(bw, "}")
	return bw.Flush()
}

func writeNode(w io.Writer, node *sbom.Node, opts *Options) {
	attrs := []string{"label=" + quote(nodeLabel(node, opts))}
	if node.GetType() == sbom.Node_FILE {
		attrs = append(attrs, "shape=note")
	}

	tooltip := []string{node.GetId()}
	if purl := string(node.Purl()); purl != "" {
		tooltip = append(tooltip, purl)
	}
	if lic := node.GetLicenseConcluded(); lic != "" {
		tooltip = append(tooltip, "License: "+lic)
	}
	attrs = append(attrs, "tooltip="+quote(strings.Join(tooltip, "\n")))

	fmt.Fprintf(w, "  %s [%s];\n", quote(node.GetId()), strings.Join(attrs, " "))
}

func nodeLabel(node *sbom.Node, opts *Options) string {
	if opts.Purls {
		if purl := string(node.Purl()); purl != "" {
			return purl
		}
	}
	label := node.GetName()
	if label == "" {
		label = node.GetId()
	}
	if v := node.GetVersion(); v != "" && node.GetType() == sbom.Node_PACKAGE {
		label += "@" + v
	}
	return label
}

var escaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

// quote returns s as a DOT double-quoted string. Newlines are written
// as the \n escape Graphviz renders as a line break.
func quote(s string) string {
	return `"` + escaper.Replace(s) + `"`
}

// edge holds every relationship from one element to another, labelled
// with their SPDX relationship types.
type edge struct {
	from, to string
	labels   []string
}

// graph indexes the node list for traversal. It drops relationships
// pointing at elements the document does not define: protobom
// expresses a relationship to another document that way, and there is
// nothing to draw for it.
type graph struct {
	nodes    map[string]*sbom.Node
	order    []string
	edges    []*edge
	next     map[string][]string
	declared []string
	roots    []string
}

func newGraph(nl *sbom.NodeList, noFiles bool) *graph {
	g := &graph{
		nodes: map[string]*sbom.Node{},
		next:  map[string][]string{},
	}
	for _, node := range nl.GetNodes() {
		id := node.GetId()
		if id == "" || (noFiles && node.GetType() == sbom.Node_FILE) {
			continue
		}
		if _, dup := g.nodes[id]; !dup {
			g.order = append(g.order, id)
		}
		g.nodes[id] = node
	}

	// Relationships between the same two elements are merged into one
	// edge, so that a pair related in several ways is drawn once.
	byPair := map[[2]string]*edge{}
	for _, e := range nl.GetEdges() {
		if _, ok := g.nodes[e.GetFrom()]; !ok {
			continue
		}
		label := e.GetType().String()
		if relType, ok := spdx.RelationshipTypeForEdge(e.GetType()); ok {
			label = string(relType)
		}
		for _, to := range e.GetTo() {
			if _, ok := g.nodes[to]; !ok {
				continue
			}
			pair := [2]string{e.GetFrom(), to}
			ed, ok := byPair[pair]
			if !ok {
				ed = &edge{from: pair[0], to: pair[1]}
				byPair[pair] = ed
				g.edges = append(g.edges, ed)
				g.next[ed.from] = append(g.next[ed.from], to)
			}
			if !slices.Contains(ed.labels, label) {
				ed.labels = append(ed.labels, label)
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
	// first element of each such cycle becomes a root too, so that the
	// graph holds every element.
	g.roots = slices.Clone(g.declared)
	referenced := map[string]bool{}
	for _, e := range g.edges {
		referenced[e.to] = true
	}
	for _, id := range g.order {
		if !referenced[id] && !slices.Contains(g.roots, id) {
			g.roots = append(g.roots, id)
		}
	}
	g.roots = append(g.roots, g.cycleRoots(g.reachable(g.roots, 0))...)
	return g
}

// cycleRoots returns one element for each cycle among the elements
// not in reached that nothing outside the cycle points at, the first
// of the cycle in document order. Every element not in reached is
// reachable from those.
func (g *graph) cycleRoots(reached map[string]bool) []string {
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
		if reached[e.from] || reached[e.to] {
			continue
		}
		if component[e.from] != component[e.to] {
			entered[component[e.to]] = true
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

// documentID returns the DOT identifier of the node standing for the
// document itself, one no element uses.
func (g *graph) documentID() string {
	id := "DOCUMENT"
	for {
		if _, ok := g.nodes[id]; !ok {
			return id
		}
		id = "_" + id
	}
}

// lookup resolves an element id as given or, failing that, with the
// SPDXRef- prefix protobom strips from SPDX identifiers removed.
func (g *graph) lookup(id string) (string, bool) {
	for _, candidate := range []string{id, strings.TrimPrefix(id, "SPDXRef-")} {
		if _, ok := g.nodes[candidate]; ok {
			return candidate, true
		}
	}
	return "", false
}

// reachable returns the elements within depth levels of starts, starts
// being the first level. A depth of zero or less is unlimited.
func (g *graph) reachable(starts []string, depth int) map[string]bool {
	seen := map[string]bool{}
	g.walk(seen, starts, depth)
	return seen
}

// walk adds the elements within depth levels of starts to seen,
// without expanding those already in it.
func (g *graph) walk(seen map[string]bool, starts []string, depth int) {
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

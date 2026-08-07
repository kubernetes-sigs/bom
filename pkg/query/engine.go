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
	"errors"
	"fmt"

	"github.com/protobom/protobom/pkg/sbom"

	"sigs.k8s.io/bom/pkg/spdx"
)

type Engine struct {
	impl     engineImplementation
	Document *sbom.Document
	MaxDepth int
}

func New() *Engine {
	return &Engine{
		impl: &defaultEngineImplementation{},
	}
}

// Open reads a document from the specified path.
func (e *Engine) Open(path string) error {
	doc, err := spdx.OpenProtobom(path)
	if err != nil {
		return fmt.Errorf("opening doc: %w", err)
	}
	e.Document = doc
	return nil
}

// Query takes an expression as a string and filters the loaded document.
func (e *Engine) Query(expString string) (fr FilterResults, err error) {
	if e.Document == nil {
		return fr, errors.New("query engine has no document open")
	}

	exp, err := NewExpression(expString)
	if err != nil {
		return fr, fmt.Errorf("reading expression: %w", err)
	}

	resultSet := e.impl.resultsFromDocument(e.Document)

	for _, filter := range exp.Filters {
		resultSet = *resultSet.Apply(filter)
	}

	return resultSet, nil
}

type engineImplementation interface {
	resultsFromDocument(*sbom.Document) FilterResults
}

type defaultEngineImplementation struct{}

// resultsFromDocument seeds a result set with the document's top-level
// elements, the entries the query language considers depth zero.
func (di *defaultEngineImplementation) resultsFromDocument(doc *sbom.Document) FilterResults {
	graph := NewGraph(doc.GetNodeList())
	objects := map[string]*sbom.Node{}
	for _, node := range graph.Roots() {
		objects[node.GetId()] = node
	}
	return FilterResults{graph: graph, Objects: objects}
}

// Graph indexes a protobom node list for traversal. The legacy object
// model carried live pointers from each element to its peers, while
// protobom keeps the relationships in a separate edge list, so the
// filters need an adjacency index to walk the document.
type Graph struct {
	nodes map[string]*sbom.Node
	edges map[string][]string
	roots []string
}

// NewGraph indexes a node list. Edges pointing at nodes the list does
// not contain are dropped: they cannot be traversed and, since
// protobom expresses a relationship to another document by naming an
// element this document does not define, they are not ours to follow.
func NewGraph(nl *sbom.NodeList) *Graph {
	g := &Graph{
		nodes: map[string]*sbom.Node{},
		edges: map[string][]string{},
	}
	for _, node := range nl.GetNodes() {
		if node.GetId() == "" {
			continue
		}
		g.nodes[node.GetId()] = node
	}

	referenced := map[string]struct{}{}
	for _, edge := range nl.GetEdges() {
		from := edge.GetFrom()
		if _, ok := g.nodes[from]; !ok {
			continue
		}
		seen := map[string]struct{}{}
		for _, id := range g.edges[from] {
			seen[id] = struct{}{}
		}
		for _, to := range edge.GetTo() {
			if _, ok := g.nodes[to]; !ok {
				continue
			}
			referenced[to] = struct{}{}
			if _, dup := seen[to]; dup {
				continue
			}
			seen[to] = struct{}{}
			g.edges[from] = append(g.edges[from], to)
		}
	}

	// The document's declared roots, plus any node no relationship
	// reaches. bom's parser surfaced those unreferenced elements as
	// top-level entries too, and dropping them here would hide them
	// from every query.
	for _, id := range nl.GetRootElements() {
		if _, ok := g.nodes[id]; ok {
			g.roots = append(g.roots, id)
		}
	}
	declared := map[string]struct{}{}
	for _, id := range g.roots {
		declared[id] = struct{}{}
	}
	for _, node := range nl.GetNodes() {
		id := node.GetId()
		if id == "" {
			continue
		}
		if _, isRoot := declared[id]; isRoot {
			continue
		}
		if _, isReferenced := referenced[id]; !isReferenced {
			g.roots = append(g.roots, id)
		}
	}
	return g
}

// Node returns the node with the given identifier, nil when the graph
// does not hold it.
func (g *Graph) Node(id string) *sbom.Node {
	return g.nodes[id]
}

// Roots returns the document's top-level nodes.
func (g *Graph) Roots() []*sbom.Node {
	nodes := make([]*sbom.Node, 0, len(g.roots))
	for _, id := range g.roots {
		nodes = append(nodes, g.nodes[id])
	}
	return nodes
}

// Related returns the nodes reachable from id in a single step.
func (g *Graph) Related(id string) []*sbom.Node {
	nodes := make([]*sbom.Node, 0, len(g.edges[id]))
	for _, to := range g.edges[id] {
		nodes = append(nodes, g.nodes[to])
	}
	return nodes
}

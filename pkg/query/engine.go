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

	"sigs.k8s.io/bom/internal/sbomgraph"
	"sigs.k8s.io/bom/internal/sbomio"
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
	doc, err := sbomio.Open(path)
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
	g *sbomgraph.Graph
}

// NewGraph indexes a node list. Edges pointing at nodes the list does
// not contain are dropped: they cannot be traversed and, since
// protobom expresses a relationship to another document by naming an
// element this document does not define, they are not ours to follow.
func NewGraph(nl *sbom.NodeList) *Graph {
	return &Graph{g: sbomgraph.New(nl, nil)}
}

// Node returns the node with the given identifier, nil when the graph
// does not hold it.
func (g *Graph) Node(id string) *sbom.Node {
	return g.g.Node(id)
}

// Roots returns the document's top-level nodes: the ones it declares,
// any node no relationship reaches (bom's parser surfaced those as
// top-level entries too), and one node of each relationship cycle no
// other root leads into, so that every node is reachable from them.
func (g *Graph) Roots() []*sbom.Node {
	return g.nodes(g.g.Roots())
}

// Related returns the nodes reachable from id in a single step.
func (g *Graph) Related(id string) []*sbom.Node {
	return g.nodes(g.g.Next(id))
}

func (g *Graph) nodes(ids []string) []*sbom.Node {
	nodes := make([]*sbom.Node, 0, len(ids))
	for _, id := range ids {
		nodes = append(nodes, g.g.Node(id))
	}
	return nodes
}

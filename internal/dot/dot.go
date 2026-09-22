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

	"sigs.k8s.io/bom/internal/sbomgraph"
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
	var keep func(*sbom.Node) bool
	if opts.NoFiles {
		keep = func(node *sbom.Node) bool { return node.GetType() != sbom.Node_FILE }
	}
	g := sbomgraph.New(doc.GetNodeList(), keep)

	// The document stands one step above its top-level elements, so
	// starting from them takes one step off the depth.
	starts, levels := g.Roots(), opts.Depth
	fromDocument := opts.Root == ""
	if !fromDocument {
		root, ok := g.Lookup(opts.Root)
		if !ok {
			return fmt.Errorf("element %q not found in document", opts.Root)
		}
		starts = []string{root}
		if levels > 0 {
			levels++
		}
	}
	visible := g.Reachable(starts, levels)

	name := doc.GetMetadata().GetName()
	if name == "" {
		name = "SBOM"
	}
	bw := bufio.NewWriter(w)
	fmt.Fprintf(bw, "digraph %s {\n", quote(name))
	fmt.Fprintln(bw, "  rankdir=LR;")
	fmt.Fprintln(bw, `  node [shape=box fontname="monospace"];`)
	fmt.Fprintln(bw, `  edge [fontname="monospace" fontsize=10];`)
	docID := documentID(g)
	if fromDocument {
		fmt.Fprintf(bw, "  %s [label=%s shape=folder];\n", quote(docID), quote(name))
	}
	for _, id := range g.IDs() {
		if visible[id] {
			writeNode(bw, g.Node(id), opts)
		}
	}
	if fromDocument {
		for _, id := range g.Declared() {
			if visible[id] {
				fmt.Fprintf(bw, "  %s -> %s [label=%s];\n", quote(docID), quote(id), quote(string(spdx.DESCRIBES)))
			}
		}
	}
	for _, e := range g.Edges() {
		if visible[e.From] && visible[e.To] {
			fmt.Fprintf(bw, "  %s -> %s [label=%s];\n", quote(e.From), quote(e.To), quote(edgeLabel(e)))
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

// edgeLabel lists the relationship types of an edge by their SPDX
// names.
func edgeLabel(e *sbomgraph.Edge) string {
	labels := make([]string, 0, len(e.Types))
	for _, t := range e.Types {
		label := t.String()
		if relType, ok := spdx.RelationshipTypeForEdge(t); ok {
			label = string(relType)
		}
		if !slices.Contains(labels, label) {
			labels = append(labels, label)
		}
	}
	return strings.Join(labels, ", ")
}

// documentID returns the DOT identifier of the node standing for the
// document itself, one no element uses.
func documentID(g *sbomgraph.Graph) string {
	id := "DOCUMENT"
	for g.Node(id) != nil {
		id = "_" + id
	}
	return id
}

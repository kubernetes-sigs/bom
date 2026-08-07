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
	"regexp"

	purl "github.com/package-url/packageurl-go"
	"github.com/protobom/protobom/pkg/sbom"
)

type Filter interface {
	Apply(*Graph, map[string]*sbom.Node) (map[string]*sbom.Node, error)
}

type FilterResults struct {
	graph   *Graph
	Objects map[string]*sbom.Node
	Error   error
}

func (fr *FilterResults) Apply(filter Filter) *FilterResults {
	// If the filter results have an error. Stop here
	if fr.Error != nil {
		return fr
	}

	newObjSet, err := filter.Apply(fr.graph, fr.Objects)
	if err != nil {
		fr.Error = err
		return fr
	}
	fr.Objects = newObjSet
	return fr
}

type DepthFilter struct {
	TargetDepth int
}

func (f *DepthFilter) Apply(graph *Graph, objects map[string]*sbom.Node) (map[string]*sbom.Node, error) {
	// Perform filter
	return searchDepth(graph, objects, 0, f.TargetDepth), nil
}

func searchDepth(
	graph *Graph, objectSet map[string]*sbom.Node, currentDepth, targetDepth int,
) map[string]*sbom.Node {
	// If we are at target depth, we are done
	if targetDepth == currentDepth {
		return objectSet
	}

	res := map[string]*sbom.Node{}
	for _, o := range objectSet {
		// If not, cycle the node's relationships to search further down
		for _, peer := range graph.Related(o.GetId()) {
			res[peer.GetId()] = peer
		}
	}

	return searchDepth(graph, res, currentDepth+1, targetDepth)
}

// AllFilter matches everything.
type AllFilter struct{}

func (f *AllFilter) Apply(graph *Graph, objects map[string]*sbom.Node) (map[string]*sbom.Node, error) {
	cycler := ObjectCycler{}
	return cycler.CycleFull(graph, objects, func(*sbom.Node) bool { return true }), nil
}

type NameFilter struct {
	Pattern string
	Regexp  *regexp.Regexp
}

func (f *NameFilter) Apply(graph *Graph, objects map[string]*sbom.Node) (map[string]*sbom.Node, error) {
	// Compile the pattern once if required
	if f.Regexp == nil {
		re, err := regexp.Compile(f.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compiling pattern: %w", err)
		}
		f.Regexp = re
	}

	// Perform filter
	cycler := ObjectCycler{}
	return cycler.Cycle(graph, objects, func(node *sbom.Node) bool {
		return f.Regexp.MatchString(node.GetName())
	}), nil
}

type PurlFilter struct {
	Pattern string
}

func (f *PurlFilter) Apply(graph *Graph, objects map[string]*sbom.Node) (map[string]*sbom.Node, error) {
	patternPurl, err := purl.FromString(f.Pattern)
	if err != nil {
		return nil, fmt.Errorf("parsing purl: %w", err)
	}

	if patternPurl.Type == "" {
		patternPurl.Type = "*"
	}

	if patternPurl.Name == "" {
		patternPurl.Name = "*"
	}

	if patternPurl.Version == "" {
		patternPurl.Version = "*"
	}

	if patternPurl.Namespace == "" {
		patternPurl.Namespace = "*"
	}
	cycler := ObjectCycler{}
	return cycler.Cycle(graph, objects, func(node *sbom.Node) bool {
		return purlMatches(&patternPurl, node)
	}), nil
}

// purlMatches reports whether a node's package URL satisfies the
// pattern. Components set to "*" match anything, and every qualifier
// named in the pattern must be present on the node with the same
// value.
func purlMatches(spec *purl.PackageURL, node *sbom.Node) bool {
	raw := string(node.Purl())
	if raw == "" {
		return false
	}
	nodePurl, err := purl.FromString(raw)
	if err != nil {
		return false
	}

	if spec.Type != "*" && spec.Type != nodePurl.Type {
		return false
	}
	if spec.Namespace != "*" && spec.Namespace != nodePurl.Namespace {
		return false
	}
	if spec.Name != "*" && spec.Name != nodePurl.Name {
		return false
	}
	if spec.Version != "*" && spec.Version != nodePurl.Version {
		return false
	}
	if spec.Subpath != "*" && spec.Subpath != nodePurl.Subpath {
		return false
	}

	// Compare the qualifiers
	specQs := spec.Qualifiers.Map()
	pkgQs := nodePurl.Qualifiers.Map()

	for k := range specQs {
		if _, ok := pkgQs[k]; !ok {
			return false
		}
		if specQs[k] != pkgQs[k] {
			return false
		}
	}
	return true
}

type MatcherFunction func(*sbom.Node) bool

type ObjectCycler struct{}

func (cycler *ObjectCycler) Cycle(
	graph *Graph, objects map[string]*sbom.Node, fn MatcherFunction,
) map[string]*sbom.Node {
	return doRecursion(graph, objects, fn, map[string]struct{}{})
}

func (cycler *ObjectCycler) CycleFull(
	graph *Graph, objects map[string]*sbom.Node, fn MatcherFunction,
) map[string]*sbom.Node {
	return doFullRecursion(graph, objects, fn, map[string]struct{}{})
}

// doRecursion will traverse the SBOM graph and return the element that
// matches the query without continuing down its relationships.
func doRecursion(
	graph *Graph, objects map[string]*sbom.Node, fn MatcherFunction, seen map[string]struct{},
) map[string]*sbom.Node {
	newSet := map[string]*sbom.Node{}
	for _, o := range objects {
		if o.GetId() == "" {
			continue
		}
		if _, ok := seen[o.GetId()]; ok {
			continue
		}
		seen[o.GetId()] = struct{}{}

		if fn(o) {
			newSet[o.GetId()] = o
			continue
		}

		// do a new recursion on the related nodes
		subSet := map[string]*sbom.Node{}
		for _, peer := range graph.Related(o.GetId()) {
			subSet[peer.GetId()] = peer
		}
		for id, node := range doRecursion(graph, subSet, fn, seen) {
			newSet[id] = node
		}
	}
	return newSet
}

// doFullRecursion will probe all nodes in the sbom, when matching a
// node, it will continue traversing its relationships returning all
// matching nodes in a flat array.
func doFullRecursion(
	graph *Graph, objects map[string]*sbom.Node, fn MatcherFunction, seen map[string]struct{},
) map[string]*sbom.Node {
	newSet := map[string]*sbom.Node{}
	for _, o := range objects {
		if o.GetId() == "" {
			continue
		}
		if _, ok := seen[o.GetId()]; ok {
			continue
		}
		seen[o.GetId()] = struct{}{}

		if fn(o) {
			newSet[o.GetId()] = o
		}

		// do a new recursion on the related nodes
		subSet := map[string]*sbom.Node{}
		for _, peer := range graph.Related(o.GetId()) {
			subSet[peer.GetId()] = peer
		}
		for id, node := range doFullRecursion(graph, subSet, fn, seen) {
			newSet[id] = node
		}
	}
	return newSet
}

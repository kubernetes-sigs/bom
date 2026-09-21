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
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/carabiner-dev/unpack/image"
	"github.com/google/uuid"
	purl "github.com/package-url/packageurl-go"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/sirupsen/logrus"
)

// layerNodeComment is the marker unpack's image unpacker leaves on the
// structural layer nodes it records.
const layerNodeComment = "container image layer"

// addImages scans each image reference into a top-level package.
func addImages(ctx context.Context, doc *sbom.Document, opts *Options) error {
	if len(opts.Images) == 0 {
		return nil
	}
	if opts.Offline {
		return errors.New("cannot scan image references offline")
	}
	for _, ref := range opts.Images {
		nl, err := imageNodeList(ctx, &image.Reference{Ref: ref})
		if err != nil {
			return fmt.Errorf("scanning image %q: %w", ref, err)
		}
		addSourceNodeList(doc, nl)
	}
	return nil
}

// addImageArchives resolves the archive patterns and scans each
// matching docker-archive tarball into a top-level package.
func addImageArchives(ctx context.Context, doc *sbom.Document, opts *Options) error {
	for _, pattern := range opts.ImageArchives {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return fmt.Errorf("globbing %q: %w", pattern, err)
		}
		if len(matches) == 0 {
			logrus.Warnf("no image archives matched pattern %q", pattern)
			continue
		}
		for _, path := range matches {
			info, err := os.Stat(path)
			if err != nil {
				return fmt.Errorf("checking %q: %w", path, err)
			}
			if info.IsDir() {
				continue
			}
			nl, err := imageNodeList(ctx, &image.Reference{Archive: path})
			if err != nil {
				return fmt.Errorf("scanning image archive %q: %w", path, err)
			}
			addSourceNodeList(doc, nl)
		}
	}
	return nil
}

// imageNodeList runs unpack's image unpacker on the subject and gives
// the resulting structural nodes deterministic identifiers.
func imageNodeList(ctx context.Context, subject *image.Reference) (*sbom.NodeList, error) {
	registerGoBinaryDecomposer()
	unpacker := image.NewUnpacker()
	// Squash plus structural layer nodes is bom's image SBOM shape:
	// the package inventory reads from the squashed filesystem, and
	// each layer is recorded as a digest-carrying node under the
	// image, with no packages of its own.
	unpacker.Options.RecordLayers = true

	lists, err := unpacker.Extract(ctx, subject)
	if err != nil {
		return nil, err
	}
	var merged *sbom.NodeList
	for _, nl := range lists {
		if merged == nil {
			merged = nl
		} else {
			merged.Add(nl)
		}
	}
	if merged == nil {
		return nil, errors.New("image unpacker returned no nodes")
	}
	assignImageIDs(merged)
	return merged, nil
}

// assignImageIDs replaces the random identifiers unpack assigns to
// image, layer and OS package nodes with deterministic legacy-style
// element ids: image nodes seed on their name, layer nodes on their
// image's name and their own, and OS packages on their name, version,
// architecture and distribution. The Go binary packages have
// deterministic identifiers already.
func assignImageIDs(nl *sbom.NodeList) {
	parents := map[string]*sbom.Node{}
	for _, edge := range nl.GetEdges() {
		if edge.GetType() != sbom.Edge_contains {
			continue
		}
		from := nl.GetNodeByID(edge.GetFrom())
		if from == nil {
			continue
		}
		for _, to := range edge.GetTo() {
			parents[to] = from
		}
	}

	renames := map[string]string{}
	for _, node := range nl.GetNodes() {
		switch {
		case slices.Contains(node.GetPrimaryPurpose(), sbom.Purpose_CONTAINER):
			renames[node.GetId()] = elementID("Package", node.GetName())
		case node.GetComment() == layerNodeComment:
			seed := node.GetName()
			if parent := parents[node.GetId()]; parent != nil {
				seed = parent.GetName() + "-" + seed
			}
			renames[node.GetId()] = elementID("Package", seed)
		case node.GetType() == sbom.Node_PACKAGE && uuid.Validate(node.GetId()) == nil:
			renames[node.GetId()] = elementID("Package", osPackageSeed(node))
		}
	}
	// Distinct packages seeding the same identifier are numbered in
	// node order, which the unpacker keeps stable.
	taken := map[string]struct{}{}
	for _, node := range nl.GetNodes() {
		id, ok := renames[node.GetId()]
		if !ok {
			id = node.GetId()
		}
		unique := id
		for i := 1; ; i++ {
			if _, dup := taken[unique]; !dup {
				break
			}
			unique = fmt.Sprintf("%s-%04d", id, i)
		}
		taken[unique] = struct{}{}
		if unique != node.GetId() {
			renames[node.GetId()] = unique
		}
	}
	renameNodes(nl, renames)
}

// osPackageSeed returns the element id seed of an OS package node: its
// name and version, and the architecture and distribution its purl
// qualifies it with, which tell apart the packages of the platform
// images of a multi-arch index.
func osPackageSeed(node *sbom.Node) string {
	parts := []string{node.GetName()}
	if node.GetVersion() != "" {
		parts = append(parts, node.GetVersion())
	}
	if p, err := purl.FromString(string(node.Purl())); err == nil {
		qualifiers := p.Qualifiers.Map()
		for _, key := range []string{"arch", "distro"} {
			if value := qualifiers[key]; value != "" {
				parts = append(parts, value)
			}
		}
	}
	return strings.Join(parts, "-")
}

// renameNodes rewrites node identifiers in place, updating the edges
// and root elements that reference them.
func renameNodes(nl *sbom.NodeList, renames map[string]string) {
	if len(renames) == 0 {
		return
	}
	for _, node := range nl.GetNodes() {
		if newID, ok := renames[node.GetId()]; ok {
			node.Id = newID
		}
	}
	for _, edge := range nl.GetEdges() {
		if newID, ok := renames[edge.GetFrom()]; ok {
			edge.From = newID
		}
		for i, to := range edge.GetTo() {
			if newID, ok := renames[to]; ok {
				edge.To[i] = newID
			}
		}
	}
	for i, id := range nl.GetRootElements() {
		if newID, ok := renames[id]; ok {
			nl.RootElements[i] = newID
		}
	}
}

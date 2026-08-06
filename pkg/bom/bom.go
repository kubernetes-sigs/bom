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

// Package bom is bom's protobom-native public API. It returns SBOM
// data as protobom documents (github.com/protobom/protobom), the
// format-neutral model the generation engine works in, which protobom
// serializes to SPDX or CycloneDX in any of its supported encodings.
//
// New integrations should prefer this package over the legacy
// pkg/spdx object model, which remains supported as a compatibility
// layer for existing consumers.
package bom

import (
	"context"

	"github.com/protobom/protobom/pkg/sbom"

	"sigs.k8s.io/bom/internal/generate"
)

// GenerateOptions configures a generation run. The zero value
// produces an empty document with default metadata.
type GenerateOptions struct {
	// Name is the document name. Left empty, downstream serializers
	// generate one.
	Name string

	// Namespace is the document namespace URI. Left empty, a unique
	// namespace is generated.
	Namespace string

	// CreatorPerson identifies the document author, in the SPDX
	// actor form "Name (email)".
	CreatorPerson string

	// Directories lists paths, or glob patterns, of source
	// directories to scan into top-level packages: codebases
	// recognized at the directory root (a go.mod, for example)
	// contribute their dependency graph, and the directory tree is
	// indexed into contained file nodes.
	Directories []string

	// Files lists paths, or glob patterns, of plain files to add to
	// the document as top-level elements with their checksums.
	Files []string

	// IgnorePatterns holds extra gitignore-syntax patterns applied
	// when scanning directories, in addition to each directory's own
	// .gitignore.
	IgnorePatterns []string

	// Offline disables all network access during generation. Data
	// that needs the network, such as transitive Go module graphs
	// and license lookups, degrades to what the local sources
	// declare.
	Offline bool
}

// Generate scans the requested sources and returns the SBOM as a
// protobom document.
func Generate(ctx context.Context, opts *GenerateOptions) (*sbom.Document, error) {
	if opts == nil {
		opts = &GenerateOptions{}
	}
	return generate.Document(ctx, &generate.Options{
		Name:           opts.Name,
		Namespace:      opts.Namespace,
		CreatorPerson:  opts.CreatorPerson,
		Directories:    opts.Directories,
		Files:          opts.Files,
		IgnorePatterns: opts.IgnorePatterns,
		Offline:        opts.Offline,
	})
}

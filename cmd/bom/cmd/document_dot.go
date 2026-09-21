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

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"sigs.k8s.io/bom/internal/dot"
	"sigs.k8s.io/bom/pkg/bom"
)

func AddDot(parent *cobra.Command) {
	dotOpts := &dot.Options{}
	dotCmd := &cobra.Command{
		PersistentPreRunE: initLogging,
		Short:             "bom document dot → Export the SBOM graph in Graphviz DOT format",
		Long: `bom document dot → Export the SBOM graph in Graphviz DOT format

This subcommand writes the relationship graph of an SBOM in the DOT
language (https://graphviz.org/doc/info/lang.html) to STDOUT, ready to
be rendered with Graphviz or any other tool that reads DOT:

  bom document dot sbom.spdx.json | dot -Tsvg > sbom.svg

Unlike the tree drawn by 'bom document outline', every element appears
once: an element related to several others is a single node with an
edge from each of them, and each edge is labelled with its SPDX
relationship types.

Use --root to render only the part of the graph reachable from one
element, and --depth to limit how many relationship steps are followed.
For example, --depth=1 renders only the elements at the top level of
the document, or with --root, the root element and the elements it
relates to directly. Large SBOMs are easier to read with --no-files,
which leaves file elements out.

SPDX documents in JSON or tag-value and CycloneDX documents are
supported. The document can also be read from a URL or piped on STDIN
by specifying the path as a dash (-) or omitting it.
`,
		Use:           "dot SBOM_FILE|URL",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				args = append(args, "")
			}
			doc, err := bom.Open(args[0])
			if err != nil {
				return fmt.Errorf("opening doc: %w", err)
			}
			if err := dot.Write(os.Stdout, doc, dotOpts); err != nil {
				return fmt.Errorf("rendering graph: %w", err)
			}
			return nil
		},
	}
	dotCmd.PersistentFlags().StringVarP(
		&dotOpts.Root,
		"root",
		"r",
		"",
		"ID of the element to render the graph from, instead of the document",
	)
	dotCmd.PersistentFlags().IntVarP(
		&dotOpts.Depth,
		"depth",
		"d",
		-1,
		"number of relationship steps to follow, zero or negative for all",
	)
	dotCmd.PersistentFlags().BoolVar(
		&dotOpts.Purls,
		"purl",
		false,
		"label packages with their package URL instead of name@version",
	)

	dotCmd.PersistentFlags().BoolVar(
		&dotOpts.NoFiles,
		"no-files",
		false,
		"leave file elements out of the graph",
	)

	parent.AddCommand(dotCmd)
}

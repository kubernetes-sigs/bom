/*
Copyright 2023 The Kubernetes Authors.

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

	"github.com/spf13/cobra"

	"sigs.k8s.io/bom/pkg/bom"
	"sigs.k8s.io/bom/pkg/spdx"
)

func AddOutline(parent *cobra.Command) {
	outlineOpts := &spdx.DrawingOptions{}
	outlineCmd := &cobra.Command{
		PersistentPreRunE: initLogging,
		Short:             "bom document outline → Draw structure of a SPDX document",
		Long: `bom document outline → Draw structure of a SPDX document

This subcommand draws a tree-like outline to help the user visualize
the structure of the bom. Even when an SBOM represents a graph structure,
drawing a tree helps a lot to understand what is contained in the document.
To see each element only once, with all the relationships leading to it,
export the graph with 'bom document dot' instead.

You can define a level of depth to limit the expansion of the entities.
For example set --depth=1 to only visualize the files and packages
attached directly to the root of the document.

Packages are labelled with their name and version, or with their package
URL when --purl is set; --version=false drops the versions and
--spdx-ids replaces the labels with the SPDX identifiers of the entities.

To see where a package comes from, --find NAME draws only the branches of
the tree that lead to elements named NAME.

SPDX documents in JSON or tag-value and CycloneDX documents are
supported. The document can also be read from a URL or piped on STDIN
by specifying the path as a dash (-) or omitting it.

`,
		Use:           "outline SPDX_FILE|URL",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				args = append(args, "")
			}
			doc, err := openLegacyDoc(args[0])
			if err != nil {
				return err
			}
			if outlineOpts.Find != "" {
				doc.FilterReverseDependencies(outlineOpts.Find, outlineOpts.Recursion)
			}
			output, err := doc.Outline(outlineOpts)
			if err != nil {
				return fmt.Errorf("generating document outline: %w", err)
			}
			fmt.Println(spdx.Banner())
			fmt.Println(output)
			return nil
		},
	}
	outlineCmd.PersistentFlags().IntVarP(
		&outlineOpts.Recursion,
		"depth",
		"d",
		-1,
		"recursion level",
	)

	outlineCmd.PersistentFlags().BoolVar(
		&outlineOpts.OnlyIDs,
		"spdx-ids",
		false,
		"use SPDX identifiers in tree nodes instead of names",
	)
	outlineCmd.PersistentFlags().BoolVar(
		&outlineOpts.Version,
		"version",
		true,
		"show versions along with package names",
	)
	outlineCmd.PersistentFlags().BoolVar(
		&outlineOpts.Purls,
		"purl",
		false,
		"show package urls instead of name@version",
	)
	outlineCmd.PersistentFlags().StringVarP(
		&outlineOpts.Find,
		"find",
		"f",
		"",
		"only draw the branches leading to elements with this name",
	)

	parent.AddCommand(outlineCmd)
}

// openLegacyDoc reads an SBOM into the legacy object model, which the
// outline renderer and the file validation still work on.
func openLegacyDoc(path string) (*spdx.Document, error) {
	pdoc, err := bom.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening doc: %w", err)
	}
	doc, err := spdx.FromProtobom(pdoc)
	if err != nil {
		return nil, fmt.Errorf("opening doc: converting document: %w", err)
	}
	return doc, nil
}

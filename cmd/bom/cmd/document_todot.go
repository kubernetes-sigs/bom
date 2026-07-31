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

	"sigs.k8s.io/bom/pkg/spdx"
)

func AddToDot(parent *cobra.Command) {
	toDotOpts := &spdx.ToDotOptions{}
	toDotCmd := &cobra.Command{
		PersistentPreRunE: initLogging,
		Short:             "bom document todot -> dump the SPDX document as dotlang.",
		Long: `bom document todot -> dump the SPDX document as dotlang.

This Subcommand translates the graph like structure of an spdx document into dotlang,
An abstract grammar used to represent graphs https://graphviz.org/doc/info/lang.html.

This is printed to stdout but can easily be piped to a file like so.

bom document todot file.spdx > file.dot

The output can also be filtered by depth, (--depth), inverse dependencies (--find)
or subgraph (--subgraph) to aid with visualisation by tools like Graphviz

bom will try to add useful information to dotlangs tooltip node attribute.
`,
		Use:           "todot SPDX_FILE|URL",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				args = append(args, "")
			}
			doc, err := spdx.OpenDoc(args[0])
			if err != nil {
				return fmt.Errorf("opening doc: %w", err)
			}
			if toDotOpts.Find != "" {
				doc.FilterReverseDependencies(toDotOpts.Find, toDotOpts.Depth)
			}
			fmt.Println(doc.ToDot(toDotOpts))
			return nil
		},
	}
	toDotCmd.PersistentFlags().StringVarP(
		&toDotOpts.Find,
		"find",
		"f",
		"",
		"Find node in DAG",
	)
	toDotCmd.PersistentFlags().IntVarP(
		&toDotOpts.Depth,
		"depth",
		"d",
		-1,
		"Depth to traverse",
	)
	toDotCmd.PersistentFlags().StringVarP(
		&toDotOpts.SubGraphRoot,
		"subgraph",
		"s",
		"",
		"SPDXID of the root node for the subgraph",
	)
	parent.AddCommand(toDotCmd)
}

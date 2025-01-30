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

package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"sigs.k8s.io/bom/pkg/query"
)

type queryOptions struct {
	purl   bool
	format string
	fields []string
}

func AddQuery(parent *cobra.Command) {
	queryOpts := queryOptions{}

	queryCmd := &cobra.Command{
		PersistentPreRunE: initLogging,
		Short:             "bom document query → Search for information in an SBOM",
		Long: `bom document query → Search for information in an SBOM

The query subcommand creates a way to extract information
from an SBOM. It exposes a simple search language to filter
elements in the sbom that match a certain criteria.

The query interface allows the number of filters to grow
over time. The following filters are available:

  depth:N       The depth filter will match elements
                reachable at N levels from the document root.
                For example, to find all elements, one level
                deep from the SBOM top level:

                bom document query sbom.spdx.json "depth:1"


  name:pattern  Matches all elements in the document that
                match the regex <pattern> in their name. For example,
                to find all packages with 'lib' and a 'c' in their name:

                bom document query sbom.spdx.json 'name:lib.*c'

  purl:pattern  Matchess all elements in the document that match
                fragments of a purl. For example, to get all container
                images listed in an SBOM you can issue a query like this:

                bom document query sbom.spdx.json 'purl:pkg:/oci/*'

You can query files piped on STDIN by specifying the path as a dash (-) or
omitting it completely. These are equivalent:

    cat sbom.spdx.json | bom document query - 'name:log4j'
    cat sbom.spdx.json | bom document query 'name:log4j'

Example:

  # Match all second level elements with log4j in their name:
  bom document query sbom.spdx "depth:2 name:log4j"

`,
		Use:           "query sbom.spdx.json \"query expression\" ",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			var path string
			var queryString string
			if len(args) < 2 {
				if len(args) == 1 {
					fi, err := os.Stdin.Stat()
					if err != nil {
						return fmt.Errorf("checking stdin for data: %w", err)
					}
					if (fi.Mode() & os.ModeCharDevice) != 0 {
						cmd.Help() //nolint:errcheck
						return errors.New("document path not specified")
					}

					path = "-"
					queryString = strings.Join(args, " ")
				}

				if path == "" {
					cmd.Help() //nolint:errcheck
					return errors.New("no file or query specified")
				}
			} else {
				path = args[0]
				queryString = strings.Join(args[1:], " ")
			}

			q := query.New()
			if err := q.Open(path); err != nil {
				return fmt.Errorf("opening document %s: %w", args[0], err)
			}
			fp, err := q.Query(queryString)
			if err != nil {
				return fmt.Errorf("querying document: %w", err)
			}

			if fp.Error != nil {
				return fmt.Errorf("filter query returned an error: %w", fp.Error)
			}

			if len(fp.Objects) == 0 {
				logrus.Warning("No objects in the SBOM match the query")
			}

			var p Printer

			switch queryOpts.format {
			case "text":
				p = &LinePrinter{}
			case "csv":
				p = &CSVPrinter{}
			case "json":
				p = &JSONPrinter{}
			default:
				return errors.New("unrecognized output format, must be text, csv or json")
			}

			return p.PrintObjectList(queryOpts, fp.Objects, os.Stdout)
		},
	}
	queryCmd.PersistentFlags().BoolVar(
		&queryOpts.purl,
		"purl",
		false,
		"output package urls instead of name@version",
	)

	queryCmd.PersistentFlags().StringVar(
		&queryOpts.format,
		"format",
		"text",
		"format of output, one of: text, csv or json",
	)

	queryCmd.PersistentFlags().StringSliceVar(
		&queryOpts.fields,
		"fields",
		[]string{"name"},
		"fields to include in output, separated by commas: name,version,license,supplier,originator,url,",
	)
	parent.AddCommand(queryCmd)
}

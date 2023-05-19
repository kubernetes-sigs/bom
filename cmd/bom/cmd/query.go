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
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"sigs.k8s.io/bom/pkg/query"
	"sigs.k8s.io/bom/pkg/spdx"
)

type queryOptions struct {
	purl bool
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

  name:pattern  Matches all elements in the document that
                match the regex <pattern> in their name. For example,
				to find all packages with 'lib' and a 'c' in their name:

				bom document query sbom.spdx.json 'name:lib.*c'

  purl:pattern  Matchess all elements in the document that match
                fragments of a purl. For example, to get all container
				images listed in an SBOM you can issue a query like this:

				bom document query sbom.spdx.json 'purl:pkg:/oci/*'

Example:

  # Match all second level elements with log4j in their name:
  bom document query sbom.spdx "depth:2 name:log4j"

`,
		Use:           "query SPDX_FILE|URL \"query expression\" ",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 2 {
				cmd.Help() //nolint:errcheck
				return errors.New("you should only specify one file")
			}

			q := query.New()
			if err := q.Open(args[0]); err != nil {
				return fmt.Errorf("opening document %s: %w", args[0], err)
			}
			fp, err := q.Query(strings.Join(args[1:], " "))
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

			p = &LinePrinter{}

			p.PrintObjectList(queryOpts, fp.Objects, os.Stdout)
			return nil
		},
	}
	queryCmd.PersistentFlags().BoolVar(
		&queryOpts.purl,
		"purl",
		false,
		"output package urls instead of name@version",
	)

	parent.AddCommand(queryCmd)
}

type Printer interface {
	PrintObjectList(queryOptions, map[string]spdx.Object, io.Writer)
}

type LinePrinter struct{}

func (p *LinePrinter) PrintObjectList(opts queryOptions, objects map[string]spdx.Object, w io.Writer) {
	for _, o := range objects {
		fmt.Fprintln(w, displayQueryResult(opts, o))
	}
}

type CSVPrinter struct{}

func (p *CSVPrinter) PrintObjectList(opts queryOptions, objects map[string]spdx.Object, w io.Writer) {
	csvw := csv.NewWriter(w)
	for _, o := range objects {
		fields := []string{displayQueryResult(opts, o)}
		if err := csvw.Write(fields); err != nil {
			logrus.Fatal("writing output: %w", err)
		}
	}
	csvw.Flush()
}

type JSONPrinter struct{}

func (p *JSONPrinter) PrintObjectList(opts queryOptions, objects map[string]spdx.Object, w io.Writer) {
	type resultEntry struct {
		Name       string `json:"name,omitempty"`
		Version    string `json:"version,omitempty"`
		License    string `json:"license,omitempty"`
		Supplier   string `json:"supplier,omitempty"`
		Originator string `json:"originator,omitempty"`
		URL        string `json:"url,omitempty"`
	}
	out := []resultEntry{}
	for _, o := range objects {
		fields := resultEntry{
			Name: displayQueryResult(opts, o),
		}
		out = append(out, fields)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "    ")
	if err := enc.Encode(&out); err != nil {
		logrus.Error("encoding data: %w", err)
	}
}

func displayQueryResult(opts queryOptions, o spdx.Object) string {
	s := fmt.Sprintf("[NO NAME; ID=%s]", o.SPDXID())
	switch no := o.(type) {
	case *spdx.File:
		s = no.FileName
	case *spdx.Package:
		s = no.Name
		if no.Version != "" {
			s += fmt.Sprintf("@%s", no.Version)
		}
		if opts.purl {
			for _, er := range o.(*spdx.Package).ExternalRefs {
				if er.Type == "purl" {
					s = er.Locator
				}
			}
		}
	}
	return s
}

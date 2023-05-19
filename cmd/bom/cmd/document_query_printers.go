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
	"fmt"
	"io"

	"sigs.k8s.io/bom/pkg/spdx"
)

// Printer is an interface that takes a list of SPDX objects and
// prints to a writer a representation of it.
type Printer interface {
	PrintObjectList(queryOptions, map[string]spdx.Object, io.Writer) error
}

type LinePrinter struct{}

func (p *LinePrinter) PrintObjectList(opts queryOptions, objects map[string]spdx.Object, w io.Writer) error {
	for _, o := range objects {
		if _, err := fmt.Fprintln(w, displayQueryResult(opts, o)); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	return nil
}

type CSVPrinter struct{}

func (p *CSVPrinter) PrintObjectList(opts queryOptions, objects map[string]spdx.Object, w io.Writer) error {
	csvw := csv.NewWriter(w)
	for _, o := range objects {
		fields := []string{displayQueryResult(opts, o)}
		if err := csvw.Write(fields); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	csvw.Flush()
	return nil
}

type JSONPrinter struct{}

func (p *JSONPrinter) PrintObjectList(opts queryOptions, objects map[string]spdx.Object, w io.Writer) error {
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
		return fmt.Errorf("encoding data: %w", err)
	}
	return nil
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

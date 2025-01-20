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
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"

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
		fields := []string{}
		for _, field := range opts.fields {
			val, err := getObjectField(opts, o, field)
			if err != nil {
				return fmt.Errorf("getting value for field %s: %w", field, err)
			}
			if val == "" {
				val = "_"
			}
			fields = append(fields, val)
		}
		fmt.Fprintln(w, strings.Join(fields, " "))
	}
	return nil
}

type CSVPrinter struct{}

func (p *CSVPrinter) PrintObjectList(opts queryOptions, objects map[string]spdx.Object, w io.Writer) error {
	csvw := csv.NewWriter(w)
	for _, o := range objects {
		fields := []string{}
		for _, field := range opts.fields {
			value, err := getObjectField(opts, o, field)
			if err != nil {
				return fmt.Errorf("getting value for field %s", field)
			}
			fields = append(fields, value)
		}
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
		fields := resultEntry{}

		for _, field := range opts.fields {
			fieldValue, err := getObjectField(opts, o, field)
			if err != nil {
				return fmt.Errorf("getting value for field %s: %w", field, err)
			}

			switch field {
			case "name":
				fields.Name = fieldValue
			case "version":
				fields.Version = fieldValue
			case "license":
				fields.License = fieldValue
			case "supplier":
				fields.Supplier = fieldValue
			case "originator":
				fields.Supplier = fieldValue
			case "url":
				fields.URL = fieldValue
			default:
				return fmt.Errorf("unknown or not supported field: %s", field)
			}
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
		if opts.purl {
			for _, er := range o.(*spdx.Package).ExternalRefs { //nolint: errcheck
				if er.Type == "purl" {
					s = er.Locator
				}
			}
		}
	}
	return s
}

func getObjectField(opts queryOptions, o spdx.Object, field string) (string, error) {
	switch field {
	case "name":
		return displayQueryResult(opts, o), nil
	case "version":
		if _, ok := o.(*spdx.Package); ok {
			return o.(*spdx.Package).Version, nil //nolint: errcheck
		}
	case "license":
		switch c := o.(type) {
		case *spdx.Package:
			if c.LicenseDeclared != "" && c.LicenseDeclared != spdx.NOASSERTION {
				return c.LicenseDeclared, nil
			} else if c.LicenseConcluded == spdx.NOASSERTION {
				return "", nil
			}
			return c.LicenseConcluded, nil
		case *spdx.File:
			return c.LicenseInfoInFile, nil
		}
	case "supplier":
		if _, ok := o.(*spdx.Package); ok {
			if o.(*spdx.Package).Supplier.Organization != "" { //nolint: errcheck
				return o.(*spdx.Package).Supplier.Organization, nil //nolint: errcheck
			}
			return o.(*spdx.Package).Supplier.Person, nil //nolint: errcheck
		}
	case "originator":
		if _, ok := o.(*spdx.Package); ok {
			if o.(*spdx.Package).Originator.Organization != "" { //nolint: errcheck
				return o.(*spdx.Package).Originator.Organization, nil //nolint: errcheck
			}
			return o.(*spdx.Package).Originator.Person, nil //nolint: errcheck
		}
	case "url":
		if _, ok := o.(*spdx.Package); ok {
			return o.(*spdx.Package).DownloadLocation, nil //nolint: errcheck
		}
	default:
		return "", fmt.Errorf("unknown or not supported field: %s", field)
	}
	return "", nil
}

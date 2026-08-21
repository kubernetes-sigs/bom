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

	"github.com/protobom/protobom/pkg/sbom"

	"sigs.k8s.io/bom/pkg/spdx"
)

// Printer is an interface that takes a list of SPDX objects and
// prints to a writer a representation of it.
type Printer interface {
	PrintObjectList(queryOptions, map[string]*sbom.Node, io.Writer) error
}

type LinePrinter struct{}

func (p *LinePrinter) PrintObjectList(opts queryOptions, objects map[string]*sbom.Node, w io.Writer) error {
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

func (p *CSVPrinter) PrintObjectList(opts queryOptions, objects map[string]*sbom.Node, w io.Writer) error {
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

func (p *JSONPrinter) PrintObjectList(opts queryOptions, objects map[string]*sbom.Node, w io.Writer) error {
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

// displayQueryResult renders the identity of a node: its name, or its
// package URL when the caller asked for purls.
func displayQueryResult(opts queryOptions, node *sbom.Node) string {
	if opts.purl && node.GetType() == sbom.Node_PACKAGE {
		if p := string(node.Purl()); p != "" {
			return p
		}
	}
	if name := node.GetName(); name != "" {
		return name
	}
	return fmt.Sprintf("[NO NAME; ID=%s]", node.GetId())
}

// actorName renders the first entry of a list of people or
// organizations the way SPDX names them.
func actorName(actors []*sbom.Person) string {
	if len(actors) == 0 {
		return ""
	}
	return actors[0].ToSPDX2ClientString()
}

func getObjectField(opts queryOptions, node *sbom.Node, field string) (string, error) {
	isPackage := node.GetType() == sbom.Node_PACKAGE
	switch field {
	case "name":
		return displayQueryResult(opts, node), nil
	case "version":
		if isPackage {
			return node.GetVersion(), nil
		}
	case "license":
		// Packages declare their license and may conclude a different
		// one; files carry the licenses found in them.
		declared := strings.Join(node.GetLicenses(), " OR ")
		if !isPackage {
			return strings.Join(node.GetLicenses(), " AND "), nil
		}
		if declared != "" && declared != spdx.NOASSERTION {
			return declared, nil
		}
		if node.GetLicenseConcluded() == spdx.NOASSERTION {
			return "", nil
		}
		return node.GetLicenseConcluded(), nil
	case "supplier":
		if isPackage {
			return actorName(node.GetSuppliers()), nil
		}
	case "originator":
		if isPackage {
			return actorName(node.GetOriginators()), nil
		}
	case "url":
		if isPackage {
			return node.GetUrlDownload(), nil
		}
	default:
		return "", fmt.Errorf("unknown or not supported field: %s", field)
	}
	return "", nil
}

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

package bom

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/blang/semver/v4"
	"github.com/protobom/protobom/pkg/sbom"

	"sigs.k8s.io/bom/pkg/license"
	"sigs.k8s.io/bom/pkg/serialize"
	"sigs.k8s.io/bom/pkg/spdx"
)

// Format is an SPDX encoding Write renders documents in.
type Format string

const (
	// FormatJSON is SPDX 2.3 JSON.
	FormatJSON Format = "json"

	// FormatTagValue is SPDX 2.3 tag-value.
	FormatTagValue Format = "tag-value"
)

// WriteOptions configures Write. The zero value writes SPDX JSON.
type WriteOptions struct {
	// Format is the encoding to write, FormatJSON when left empty.
	Format Format

	// LicenseListVersion is the version of the SPDX license list the
	// document declares, trimmed to major.minor. Left empty, the
	// version of the list bom ships with is declared. protobom does
	// not keep the version a document it read declared, so a document
	// read with Open and written again declares this one too.
	LicenseListVersion string
}

// Write renders a protobom document as SPDX to w, producing the same
// output as bom generate does for the same document, short of the
// newline bom generate appends when it writes to STDOUT.
//
// The document's own creators are kept; only a document crediting no
// organization is credited to Kubernetes Release Engineering, as bom
// generate does.
//
// Documents can also be written with protobom's own writer, in any
// format it supports; the output then differs in the details bom
// fills in, like the tool and organization credits.
func Write(w io.Writer, doc *sbom.Document, opts *WriteOptions) error {
	if opts == nil {
		opts = &WriteOptions{}
	}

	var renderer serialize.Serializer
	switch opts.Format {
	case FormatJSON, "":
		renderer = &serialize.JSON{}
	case FormatTagValue:
		renderer = &serialize.TagValue{}
	default:
		return fmt.Errorf("unsupported format %q", opts.Format)
	}

	ldoc, err := legacyDocument(doc, opts.LicenseListVersion)
	if err != nil {
		return err
	}
	markup, err := renderer.Serialize(ldoc)
	if err != nil {
		return fmt.Errorf("serializing document: %w", err)
	}
	if _, err := io.WriteString(w, markup); err != nil {
		return fmt.Errorf("writing document: %w", err)
	}
	return nil
}

// legacyDocument converts a document to the object model bom's SPDX
// serializers render, completing it the way spdx.DocBuilder completes
// the documents bom generate writes.
func legacyDocument(doc *sbom.Document, licenseListVersion string) (*spdx.Document, error) {
	if doc == nil {
		return nil, errors.New("document is nil")
	}
	ldoc, err := spdx.FromProtobom(doc)
	if err != nil {
		return nil, fmt.Errorf("converting document: %w", err)
	}

	ver := strings.TrimPrefix(license.DefaultCatalogOpts.Version, "v")
	if licenseListVersion != "" {
		ver = strings.TrimPrefix(licenseListVersion, "v")
	}
	v, err := semver.New(ver)
	if err != nil {
		return nil, fmt.Errorf("parsing license list semver string %q: %w", ver, err)
	}
	ldoc.LicenseListVersion = fmt.Sprintf("%d.%d", v.Major, v.Minor)
	if ldoc.Creator.Organization == "" {
		ldoc.Creator.Organization = "Kubernetes Release Engineering"
	}
	return ldoc, nil
}

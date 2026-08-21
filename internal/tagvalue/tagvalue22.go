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

package tagvalue

// The SPDX 2.2 drivers. Unlike SPDX 2.3, where protobom ships the JSON
// implementation and only tag-value is filled in here, protobom has no
// SPDX 2.2 implementation at all, so both encodings live in this file.
// Old Kubernetes release SBOMs (up to 1.23) are SPDX 2.2.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/native/unserializers"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/spdx/tools-golang/convert"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	v2_2 "github.com/spdx/tools-golang/spdx/v2/v2_2"
	"github.com/spdx/tools-golang/tagvalue"
)

// noassertion is the SPDX marker for fields whose value the document
// creator makes no claim about.
const noassertion = "NOASSERTION"

// Serializer22 writes protobom documents as SPDX 2.2 in JSON encoding.
// The document is built with the SPDX 2.3 mapping and downgraded
// through the tools-golang conversion chain, degrading the data that
// SPDX 2.2 cannot express (see downgradeDocument).
type Serializer22 struct {
	Serializer
}

var _ native.Serializer = (*Serializer22)(nil)

func NewSerializer22() *Serializer22 {
	return &Serializer22{Serializer: *NewSerializer()}
}

// Serialize converts a protobom document to an SPDX 2.2 document. It
// accepts the same raw options as protobom's SPDX 2.3 serializer.
func (s *Serializer22) Serialize(bom *sbom.Document, opts *native.SerializeOptions, rawopts any) (any, error) {
	doc, err := s.Serializer.Serialize(bom, opts, rawopts)
	if err != nil {
		return nil, err
	}
	doc23, ok := doc.(*spdx.Document)
	if !ok {
		return nil, errors.New("unable to cast serialized document as SPDX 2.3")
	}
	doc22 := v2_2.Document{}
	if err := convert.Document(doc23, &doc22); err != nil {
		return nil, fmt.Errorf("downgrading document to SPDX 2.2: %w", err)
	}
	downgradeDocument(&doc22)
	return &doc22, nil
}

// Render writes a serialized SPDX 2.2 document to the stream in JSON
// encoding.
func (s *Serializer22) Render(doc any, w io.Writer, opts *native.RenderOptions, _ any) error {
	doc22, ok := doc.(*v2_2.Document)
	if !ok {
		return errors.New("unable to cast doc as SPDX 2.2 document")
	}
	if opts == nil {
		opts = &native.RenderOptions{}
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", strings.Repeat(" ", opts.Indent))
	if err := encoder.Encode(doc22); err != nil {
		return fmt.Errorf("encoding sbom to stream: %w", err)
	}
	return nil
}

// Serializer22TV writes protobom documents as SPDX 2.2 in tag-value
// encoding. The conversion to the SPDX 2.2 model is shared with the
// JSON serializer, only the rendering differs.
type Serializer22TV struct {
	Serializer22
}

var _ native.Serializer = (*Serializer22TV)(nil)

func NewSerializer22TV() *Serializer22TV {
	return &Serializer22TV{Serializer22: *NewSerializer22()}
}

// Render writes a serialized SPDX 2.2 document to the stream in
// tag-value encoding.
func (s *Serializer22TV) Render(doc any, w io.Writer, _ *native.RenderOptions, _ any) error {
	doc22, ok := doc.(*v2_2.Document)
	if !ok {
		return errors.New("unable to cast doc as SPDX 2.2 document")
	}
	if err := tagvalue.Write(doc22, w); err != nil {
		return fmt.Errorf("writing SPDX tag-value: %w", err)
	}
	return nil
}

// Unserializer22 parses SPDX 2.2 documents in JSON encoding. The
// tools-golang parser reads all SPDX 2.x versions and upgrades them to
// the 2.3 model, so the document conversion is fully shared with
// protobom's SPDX 2.3 unserializer.
type Unserializer22 struct {
	spdx23 *unserializers.SPDX23
}

var _ native.Unserializer = (*Unserializer22)(nil)

func NewUnserializer22() *Unserializer22 {
	return &Unserializer22{spdx23: unserializers.NewSPDX23()}
}

// Unserialize reads an SPDX 2.2 JSON document and returns its protobom
// representation.
func (u *Unserializer22) Unserialize(r io.Reader, opts *native.UnserializeOptions, rawopts any) (*sbom.Document, error) {
	// protobom's unserializer dereferences the options unguarded.
	if opts == nil {
		opts = &native.UnserializeOptions{}
	}
	return u.spdx23.Unserialize(r, opts, rawopts) //nolint:wrapcheck // pass-through to the composed unserializer
}

// Unserializer22TV parses SPDX 2.2 documents in tag-value encoding.
// The tools-golang parser reads all SPDX 2.x versions and upgrades
// them to the 2.3 model, so the decoding and document conversion are
// fully shared with the SPDX 2.3 tag-value unserializer.
type Unserializer22TV struct {
	Unserializer
}

var _ native.Unserializer = (*Unserializer22TV)(nil)

func NewUnserializer22TV() *Unserializer22TV {
	return &Unserializer22TV{Unserializer: *NewUnserializer()}
}

// spdx22ChecksumAlgorithms lists the checksum algorithms SPDX 2.2
// defines. The algorithms 2.3 added (SHA3-*, BLAKE*, ADLER32) are
// dropped when downgrading.
var spdx22ChecksumAlgorithms = map[common.ChecksumAlgorithm]bool{
	common.SHA224: true,
	common.SHA1:   true,
	common.SHA256: true,
	common.SHA384: true,
	common.SHA512: true,
	common.MD2:    true,
	common.MD4:    true,
	common.MD5:    true,
	common.MD6:    true,
}

// downgradeDocument degrades the data of a converted document that
// SPDX 2.2 cannot express: checksum algorithms introduced in 2.3 are
// dropped, and the licensing and copyright fields that 2.3 made
// optional are backfilled with NOASSERTION as 2.2 requires them.
// Fields 2.2 does not have (such as the primary package purpose) are
// already dropped by the struct conversion.
func downgradeDocument(doc *v2_2.Document) {
	for _, p := range doc.Packages {
		p.PackageChecksums = filterChecksums22(p.PackageChecksums)
		if p.PackageDownloadLocation == "" {
			p.PackageDownloadLocation = noassertion
		}
		if p.PackageLicenseConcluded == "" {
			p.PackageLicenseConcluded = noassertion
		}
		if p.PackageLicenseDeclared == "" {
			p.PackageLicenseDeclared = noassertion
		}
		if p.PackageCopyrightText == "" {
			p.PackageCopyrightText = noassertion
		}
	}
	for _, f := range doc.Files {
		f.Checksums = filterChecksums22(f.Checksums)
		if f.LicenseConcluded == "" {
			f.LicenseConcluded = noassertion
		}
		if len(f.LicenseInfoInFiles) == 0 {
			f.LicenseInfoInFiles = []string{noassertion}
		}
		if f.FileCopyrightText == "" {
			f.FileCopyrightText = noassertion
		}
	}
}

func filterChecksums22(in []common.Checksum) []common.Checksum {
	out := make([]common.Checksum, 0, len(in))
	for _, c := range in {
		if spdx22ChecksumAlgorithms[c.Algorithm] {
			out = append(out, c)
		}
	}
	return out
}

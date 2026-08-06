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

// Package tagvalue implements the SPDX serializers and unserializers
// that protobom declares format constants for but does not implement:
// SPDX 2.3 tag-value, and SPDX 2.2 in both tag-value and JSON
// encodings. It composes protobom's SPDX 2.3 model mapping with
// spdx/tools-golang, the SPDX reference implementation, for the
// encodings and the 2.2 downgrade.
//
// The package is internal on purpose: these drivers have been
// contributed to protobom (the spdx-tv branch / open PR) and this copy
// will be dropped for the upstream ones as soon as a protobom release
// ships them. Nothing outside this module may grow a dependency on it.
//
// Call Register to make the formats available to protobom's writer and
// reader:
//
//	tagvalue.Register()
//	w := writer.New(writer.WithFormat(formats.SPDX23TV))
package tagvalue

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/native/serializers"
	"github.com/protobom/protobom/pkg/native/unserializers"
	"github.com/protobom/protobom/pkg/reader"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
	spdxjson "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/tagvalue"
)

// Serializer writes protobom documents as SPDX 2.3 tag-value. The
// protobom-to-SPDX mapping is delegated to protobom's own SPDX 2.3
// serializer so that tag-value and JSON renderings of a document stay
// consistent; only the final encoding differs.
type Serializer struct {
	spdx23 *serializers.SPDX23
}

var _ native.Serializer = (*Serializer)(nil)

func NewSerializer() *Serializer {
	return &Serializer{spdx23: serializers.NewSPDX23()}
}

// Serialize converts a protobom document to an SPDX 2.3 document. It
// accepts the same raw options as protobom's SPDX 2.3 serializer.
func (s *Serializer) Serialize(bom *sbom.Document, opts *native.SerializeOptions, rawopts any) (any, error) {
	if opts == nil {
		opts = &native.SerializeOptions{}
	}
	return s.spdx23.Serialize(bom, opts, rawopts) //nolint:wrapcheck // pass-through to the composed serializer
}

// Render writes a serialized SPDX 2.3 document to the stream in
// tag-value encoding.
func (s *Serializer) Render(doc any, w io.Writer, _ *native.RenderOptions, _ any) error {
	spdxDoc, ok := doc.(*spdx.Document)
	if !ok {
		return errors.New("unable to cast doc as SPDX 2.3 document")
	}
	if err := tagvalue.Write(spdxDoc, w); err != nil {
		return fmt.Errorf("writing SPDX tag-value: %w", err)
	}
	return nil
}

// Unserializer parses SPDX 2.3 tag-value documents into protobom.
type Unserializer struct {
	spdx23 *unserializers.SPDX23
}

var _ native.Unserializer = (*Unserializer)(nil)

func NewUnserializer() *Unserializer {
	return &Unserializer{spdx23: unserializers.NewSPDX23()}
}

// Unserialize reads an SPDX 2.3 tag-value document and returns its
// protobom representation. The tag-value text is parsed with
// spdx/tools-golang and re-encoded as SPDX JSON in memory to reuse
// protobom's SPDX-to-protobom conversion unchanged; an upstreamed
// version of this unserializer would call the conversion directly
// instead.
func (u *Unserializer) Unserialize(r io.Reader, opts *native.UnserializeOptions, rawopts any) (*sbom.Document, error) {
	// protobom's unserializer dereferences the options unguarded.
	if opts == nil {
		opts = &native.UnserializeOptions{}
	}
	doc, err := tagvalue.Read(r)
	if err != nil {
		return nil, fmt.Errorf("parsing SPDX tag-value: %w", err)
	}
	hoistPackageFiles(doc)
	var buf bytes.Buffer
	if err := spdxjson.Write(doc, &buf); err != nil {
		return nil, fmt.Errorf("re-encoding SPDX document: %w", err)
	}
	pbom, err := u.spdx23.Unserialize(&buf, opts, rawopts)
	if err != nil {
		return nil, fmt.Errorf("converting SPDX document to protobom: %w", err)
	}
	return pbom, nil
}

// hoistPackageFiles moves files nested in packages to the document
// level, keeping a CONTAINS relationship in their place. The tag-value
// parser attaches the file sections that follow a package to that
// package, but tools-golang marshals those as a files array nested in
// the package object — a shape the SPDX JSON schema does not have and
// protobom's conversion (rightly) never reads, so without hoisting the
// files would be silently dropped.
func hoistPackageFiles(doc *spdx.Document) {
	seen := map[common.ElementID]bool{}
	for _, f := range doc.Files {
		seen[f.FileSPDXIdentifier] = true
	}
	related := map[common.ElementID]map[common.ElementID]bool{}
	for _, rel := range doc.Relationships {
		if rel.Relationship == common.TypeRelationshipContains {
			if related[rel.RefA.ElementRefID] == nil {
				related[rel.RefA.ElementRefID] = map[common.ElementID]bool{}
			}
			related[rel.RefA.ElementRefID][rel.RefB.ElementRefID] = true
		}
	}
	for _, p := range doc.Packages {
		for _, f := range p.Files {
			if !seen[f.FileSPDXIdentifier] {
				doc.Files = append(doc.Files, f)
				seen[f.FileSPDXIdentifier] = true
			}
			if !related[p.PackageSPDXIdentifier][f.FileSPDXIdentifier] {
				doc.Relationships = append(doc.Relationships, &spdx.Relationship{
					RefA:         common.DocElementID{ElementRefID: p.PackageSPDXIdentifier},
					RefB:         common.DocElementID{ElementRefID: f.FileSPDXIdentifier},
					Relationship: common.TypeRelationshipContains,
				})
			}
		}
		p.Files = nil
	}
}

// Register makes the SPDX 2.3 tag-value and SPDX 2.2 formats available
// to protobom's writer and reader. SPDX 2.3 JSON needs no registration:
// protobom ships it by default.
func Register() {
	writer.RegisterSerializer(formats.SPDX23TV, NewSerializer())
	reader.RegisterUnserializer(formats.SPDX23TV, NewUnserializer())
	writer.RegisterSerializer(formats.SPDX22TV, NewSerializer22TV())
	reader.RegisterUnserializer(formats.SPDX22TV, NewUnserializer22TV())
	writer.RegisterSerializer(formats.SPDX22JSON, NewSerializer22())
	reader.RegisterUnserializer(formats.SPDX22JSON, NewUnserializer22())
}

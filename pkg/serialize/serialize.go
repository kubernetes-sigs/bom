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

package serialize

import (
	gojson "encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"sigs.k8s.io/release-utils/version"

	"sigs.k8s.io/bom/pkg/spdx"
	spdxJSON "sigs.k8s.io/bom/pkg/spdx/json/v2.3"
)

type Serializer interface {
	Serialize(*spdx.Document) (string, error)
}

type TagValue struct{}

// Serialize the documento into SPDX Tag-Value format. For now, the
// tag-value saerializer is just a wrapper around the old document.Render
// function. In future versions, the rendering logic should be moved here.
func (tv *TagValue) Serialize(doc *spdx.Document) (string, error) {
	return doc.Render()
}

type JSON struct{}

// Serialize serializes the document into a spdx JSON.
func (json *JSON) Serialize(doc *spdx.Document) (string, error) {
	// The old Render() method finalizes the sbom before serializing
	// it. We still need to call it before building the JSON struct.
	if _, err := doc.Render(); err != nil {
		return "", fmt.Errorf("pre-rendering the document: %w", err)
	}

	// The document creation date is kept when the generator set one,
	// so documents can be reproduced (SOURCE_DATE_EPOCH, for one).
	created := doc.Created
	if created.IsZero() {
		created = time.Now()
	}
	jsonDoc := spdxJSON.Document{
		ID:      doc.ID,
		Name:    doc.Name,
		Version: spdxJSON.Version,
		CreationInfo: spdxJSON.CreationInfo{
			Created: created.UTC().Format("2006-01-02T15:04:05Z07:00"),
			Creators: []string{
				fmt.Sprintf("Tool: %s-%s", "bom", version.GetVersionInfo().GitVersion),
			},
			LicenseListVersion: doc.LicenseListVersion,
		},
		DataLicense:       doc.DataLicense,
		Namespace:         doc.Namespace,
		DocumentDescribes: []string{},
		Packages:          []spdxJSON.Package{},
		Relationships:     []spdxJSON.Relationship{},
	}

	for _, ref := range doc.ExternalDocRefs {
		if ref.Validate() != nil {
			continue
		}
		algo, value := ref.Checksum()
		jsonDoc.ExternalDocumentRefs = append(jsonDoc.ExternalDocumentRefs, spdxJSON.ExternalDocumentRef{
			ExternalDocumentID: ref.DocumentRefID(),
			SPDXDocument:       ref.URI,
			Checksum:           spdxJSON.Checksum{Algorithm: algo, Value: value},
		})
	}

	// Generate the array for the cycler. The document holds its
	// elements in maps: they are listed sorted by ID to keep the
	// output stable.
	for _, id := range slices.Sorted(maps.Keys(doc.Packages)) {
		jsonDoc.DocumentDescribes = append(jsonDoc.DocumentDescribes, doc.Packages[id].SPDXID())
	}

	for _, id := range slices.Sorted(maps.Keys(doc.Files)) {
		jsonDoc.DocumentDescribes = append(jsonDoc.DocumentDescribes, doc.Files[id].SPDXID())
	}

	for _, o := range allObjects(doc) {
		if p, ok := o.(*spdx.Package); ok {
			jsonPackage, err := json.buildJSONPackage(p)
			if err != nil {
				return "", fmt.Errorf("serializing json package: %w", err)
			}
			jsonDoc.Packages = append(jsonDoc.Packages, jsonPackage)

			// Add the package's relationships to the doc
			for _, r := range *p.GetRelationships() {
				jsonDoc.Relationships = append(jsonDoc.Relationships, spdxJSON.Relationship{
					Element: p.SPDXID(),
					Type:    string(r.Type),
					Related: r.Peer.SPDXID(),
				})
			}
		}

		if f, ok := o.(*spdx.File); ok {
			jsonFile, err := json.buildJSONFile(f)
			if err != nil {
				return "", fmt.Errorf("serializing json package: %w", err)
			}
			jsonDoc.Files = append(jsonDoc.Files, jsonFile)

			// Add the package's relationships to the doc
			for _, r := range *f.GetRelationships() {
				jsonDoc.Relationships = append(jsonDoc.Relationships, spdxJSON.Relationship{
					Element: f.SPDXID(),
					Type:    string(r.Type),
					Related: r.Peer.SPDXID(),
				})
			}
		}
	}

	for _, lic := range doc.ExtractedLicenses {
		jsonDoc.ExtractedLicenses = append(jsonDoc.ExtractedLicenses, spdxJSON.ExtractedLicense{
			ID:            lic.ID,
			ExtractedText: lic.Text,
			Name:          lic.Name,
		})
	}

	output, err := gojson.MarshalIndent(jsonDoc, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling document json: %w", err)
	}
	return string(output), nil
}

// allObjects returns every element of the document: the top-level
// packages and files plus everything reachable from them through
// relationships, each once, in a stable order. Top-level elements are
// walked sorted by identifier, and their relationships depth first in
// the order they were recorded.
func allObjects(doc *spdx.Document) []spdx.Object {
	objects := []spdx.Object{}
	seen := map[string]struct{}{}
	var walk func(spdx.Object)
	walk = func(o spdx.Object) {
		id := o.SPDXID()
		if id == "" {
			return
		}
		if _, ok := seen[id]; ok {
			return
		}
		seen[id] = struct{}{}
		objects = append(objects, o)
		for _, r := range *o.GetRelationships() {
			if r.Peer != nil {
				walk(r.Peer)
			}
		}
	}
	for _, id := range slices.Sorted(maps.Keys(doc.Packages)) {
		walk(doc.Packages[id])
	}
	for _, id := range slices.Sorted(maps.Keys(doc.Files)) {
		walk(doc.Files[id])
	}
	return objects
}

// sortedChecksums converts a checksum map to the JSON list, sorted by
// algorithm to keep the output stable.
func sortedChecksums(checksums map[string]string) []spdxJSON.Checksum {
	ret := make([]spdxJSON.Checksum, 0, len(checksums))
	for _, algo := range slices.Sorted(maps.Keys(checksums)) {
		ret = append(ret, spdxJSON.Checksum{Algorithm: algo, Value: checksums[algo]})
	}
	return ret
}

// buildJSONPackage converts a SPDX package struct to a json package
// TODO(puerco): Validate package information to make sure its a valid package.
func (json *JSON) buildJSONPackage(p *spdx.Package) (jsonPackage spdxJSON.Package, err error) {
	// Update the Verification code
	if err := p.ComputeVerificationCode(); err != nil {
		return jsonPackage, fmt.Errorf("computing verification code: %w", err)
	}

	// Update the license list
	if err := p.ComputeLicenseList(); err != nil {
		return jsonPackage, fmt.Errorf("computing license list from files: %w", err)
	}

	externalRefs := make([]spdxJSON.ExternalRef, len(p.ExternalRefs))
	for i, ref := range p.ExternalRefs {
		externalRefs[i].Category = ref.Category
		externalRefs[i].Locator = ref.Locator
		externalRefs[i].Type = ref.Type
	}
	jsonPackage = spdxJSON.Package{
		ID:                   p.SPDXID(),
		Name:                 p.Name,
		Version:              p.Version,
		FileName:             p.FileName,
		FilesAnalyzed:        p.FilesAnalyzed,
		LicenseConcluded:     p.LicenseConcluded,
		LicenseDeclared:      p.LicenseDeclared,
		DownloadLocation:     p.DownloadLocation,
		LicenseInfoFromFiles: p.LicenseInfoFromFiles,
		PrimaryPurpose:       p.PrimaryPurpose,
		CopyrightText:        p.CopyrightText,
		HasFiles:             []string{},
		Checksums:            sortedChecksums(p.Checksum),
		ExternalRefs:         externalRefs,
	}

	if p.Supplier.Organization != "" {
		jsonPackage.Supplier = "Organization: " + p.Supplier.Organization
	}

	if p.Supplier.Person != "" {
		jsonPackage.Supplier = "Person: " + p.Supplier.Person
	}

	if p.VerificationCode != "" {
		jsonPackage.VerificationCode = &spdxJSON.PackageVerificationCode{
			Value: p.VerificationCode,
		}
	}

	if spdxJSON.Version == "SPDX-2.2" {
		if jsonPackage.LicenseConcluded == "" {
			jsonPackage.LicenseConcluded = spdx.NOASSERTION
		}
		if jsonPackage.LicenseDeclared == "" {
			jsonPackage.LicenseDeclared = spdx.NOASSERTION
		}
	} else {
		if jsonPackage.LicenseConcluded == spdx.NOASSERTION {
			jsonPackage.LicenseConcluded = ""
		}
		if jsonPackage.LicenseDeclared == spdx.NOASSERTION {
			jsonPackage.LicenseDeclared = ""
		}
	}

	if jsonPackage.CopyrightText == "" {
		jsonPackage.CopyrightText = spdx.NOASSERTION
	}

	if jsonPackage.DownloadLocation == "" {
		jsonPackage.DownloadLocation = spdx.NONE
	}

	// If the package has files, we need to add them top hasFiles
	files := p.Files()
	if len(files) > 0 {
		for _, f := range files {
			if f.SPDXID() == "" {
				return jsonPackage, errors.New("unable to compute has files array, file missing SPDX ID")
			}
			jsonPackage.HasFiles = append(jsonPackage.HasFiles, f.SPDXID())
		}
	}
	return jsonPackage, nil
}

// buildJSONPackage converts a SPDX package struct to a json package
// TODO(pueco): Validate file information , eg check checksums are
// enum : [ "SHA256", "SHA1", "SHA384", "MD2", "MD4", "SHA512", "MD6", "MD5", "SHA224" ]
// "required" : [ "SPDXID", "copyrightText", "fileName", "licenseConcluded" ],.
func (json *JSON) buildJSONFile(f *spdx.File) (jsonFile spdxJSON.File, err error) {
	if f.SPDXID() == "" {
		return jsonFile, errors.New("unamble to serialzie file, it has no SPDX ID defined")
	}
	jsonFile = spdxJSON.File{
		ID:            f.SPDXID(),
		Name:          f.Name,
		CopyrightText: f.CopyrightText,
		// NoticeText:        f.C,
		LicenseConcluded: f.LicenseConcluded,
		// Description:       f.Description,
		FileTypes:         f.FileType,
		LicenseInfoInFile: f.LicenseInfoInFiles(),
		Checksums:         sortedChecksums(f.Checksum),
	}

	if spdxJSON.Version == "SPDX-2.2" {
		if jsonFile.LicenseConcluded == "" {
			jsonFile.LicenseConcluded = spdx.NOASSERTION
		}
	} else {
		if jsonFile.LicenseConcluded == spdx.NOASSERTION {
			jsonFile.LicenseConcluded = ""
		}
	}

	if jsonFile.CopyrightText == "" {
		jsonFile.CopyrightText = spdx.NOASSERTION
	}

	return jsonFile, nil
}

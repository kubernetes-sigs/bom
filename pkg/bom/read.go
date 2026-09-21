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
	"io"

	"github.com/protobom/protobom/pkg/sbom"

	"sigs.k8s.io/bom/internal/sbomio"
)

// Open reads an SBOM and returns it as a protobom document. The path
// may name a file, an http(s) URL to download the document from, or
// STDIN as a dash or an empty string.
//
// Every format protobom reads is accepted, SPDX 2.2 and 2.3 in JSON
// and tag-value included, and SPDX 2.1 is read like SPDX 2.2.
// Documents that violate the SPDX specification in ways bom read
// through until v0.7.1 (a missing spdxVersion, identifiers without the
// SPDXRef- prefix, free-form package originators and suppliers in
// JSON) are repaired, with a warning, when protobom rejects them.
func Open(path string) (*sbom.Document, error) {
	return sbomio.Open(path)
}

// Parse reads an SBOM from r like Open does from a file. The input is
// buffered in memory when r is not an io.ReadSeeker, since the format
// is detected before the document is parsed.
func Parse(r io.Reader) (*sbom.Document, error) {
	return sbomio.Parse(r)
}

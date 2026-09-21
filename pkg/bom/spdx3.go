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

	"sigs.k8s.io/bom/pkg/spdx"
)

// WriteSPDX3 writes a protobom document to w as SPDX 3.0.1 JSON-LD,
// producing the same output as bom generate --format spdx3-json does
// for the same document. SPDX 3 support is experimental.
//
// The document is written with protobom's serializer after its license
// data is normalized the way the SPDX 2.3 output normalizes it. The
// document passed in is not modified.
//
// WriteSPDX3 may be folded into a generic writer taking the output
// format as an option once bom can write documents in other formats.
func WriteSPDX3(w io.Writer, doc *sbom.Document) error {
	return spdx.WriteSPDX3(w, doc)
}

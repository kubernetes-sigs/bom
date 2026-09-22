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

package bom_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"sigs.k8s.io/bom/pkg/bom"
)

func TestWriteSPDX3(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact.bin")
	require.NoError(t, os.WriteFile(path, []byte("data"), os.FileMode(0o644)))
	doc, err := bom.Generate(t.Context(), &bom.GenerateOptions{
		Name:      "public-api-spdx3",
		Namespace: "https://sbom.k8s.io/test/public-api-spdx3",
		Files:     []string{path},
	})
	require.NoError(t, err)

	var out bytes.Buffer
	require.NoError(t, bom.WriteSPDX3(&out, doc))
	var envelope struct {
		Context string `json:"@context"`
		Graph   []struct {
			Type   string `json:"type"`
			SpdxID string `json:"spdxId"`
			Name   string `json:"name"`
		} `json:"@graph"`
	}
	require.NoError(t, json.Unmarshal(out.Bytes(), &envelope))
	require.Equal(t, "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", envelope.Context)

	var documents int
	for _, el := range envelope.Graph {
		if el.Type == "SpdxDocument" {
			documents++
			require.Equal(t, "https://sbom.k8s.io/test/public-api-spdx3", el.SpdxID)
			require.Equal(t, "public-api-spdx3", el.Name)
		}
	}
	require.Equal(t, 1, documents)
}

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

package serialize_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"sigs.k8s.io/bom/pkg/serialize"
	"sigs.k8s.io/bom/pkg/spdx"
)

func TestJSONExternalDocumentRefs(t *testing.T) {
	doc := spdx.NewDocument()
	doc.ExternalDocRefs = []spdx.ExternalDocumentRef{
		{ID: "src", URI: "https://example.com/s", Checksums: map[string]string{"SHA1": "5f341d31f6b6a8b15bc4e6704830bf37f99511d1"}},
		{ID: "nosha1", URI: "https://example.com/n", Checksums: map[string]string{"SHA256": "ff"}},
	}
	out, err := (&serialize.JSON{}).Serialize(doc)
	require.NoError(t, err)

	var parsed struct {
		Refs []map[string]any `json:"externalDocumentRefs"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &parsed))
	require.Equal(t, []map[string]any{{
		"externalDocumentId": "DocumentRef-src",
		"spdxDocument":       "https://example.com/s",
		"checksum":           map[string]any{"algorithm": "SHA1", "checksumValue": "5f341d31f6b6a8b15bc4e6704830bf37f99511d1"},
	}}, parsed.Refs)
}

/*
Copyright 2021 The Kubernetes Authors.

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

package provenance_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/bom/pkg/provenance"
)

func TestWrite(t *testing.T) {
	t.Parallel()
	t.Run("write-succeeds", func(t *testing.T) {
		t.Parallel()
		p := provenance.NewSLSAPredicate()
		p.SetBuilderID("test-builder@v1")
		p.AddMaterial(&intoto.ResourceDescriptor{
			Uri:    "https://example.com/repo",
			Digest: map[string]string{"sha256": "abc123"},
		})

		tmp := filepath.Join(t.TempDir(), "predicate.json")
		require.NoError(t, p.Write(tmp))

		data, err := os.ReadFile(tmp)
		require.NoError(t, err)
		require.True(t, json.Valid(data), "output should be valid JSON")

		var parsed struct {
			Builder struct {
				ID string `json:"id"`
			} `json:"builder"`
			Materials []struct {
				URI    string            `json:"uri"`
				Digest map[string]string `json:"digest"`
			} `json:"materials"`
		}
		require.NoError(t, json.Unmarshal(data, &parsed))
		require.Equal(t, "test-builder@v1", parsed.Builder.ID)
		require.Len(t, parsed.Materials, 1)
		require.Equal(t, "https://example.com/repo", parsed.Materials[0].URI)
		require.Equal(t, "abc123", parsed.Materials[0].Digest["sha256"])
	})

	t.Run("write-empty-predicate", func(t *testing.T) {
		t.Parallel()
		p := provenance.NewSLSAPredicate()

		tmp := filepath.Join(t.TempDir(), "empty-predicate.json")
		require.NoError(t, p.Write(tmp))

		data, err := os.ReadFile(tmp)
		require.NoError(t, err)
		require.True(t, json.Valid(data))

		var parsed struct {
			Builder   map[string]any `json:"builder"`
			Materials []any          `json:"materials"`
		}
		require.NoError(t, json.Unmarshal(data, &parsed))
		require.NotNil(t, parsed.Builder)
		require.Empty(t, parsed.Materials)
	})

	t.Run("write-fails", func(t *testing.T) {
		p := provenance.NewSLSAPredicate()
		err := p.Write("/nonexistent-dir/predicate.json")
		require.Error(t, err)
	})
}

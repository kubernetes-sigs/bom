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

package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"

	"sigs.k8s.io/bom/pkg/spdx"
)

func TestBuildSplitOutputFile(t *testing.T) {
	for _, tc := range []struct {
		name     string
		input    string
		lang     string
		expected string
	}{
		{
			name:     "simple extension",
			input:    "output.spdx",
			lang:     "go",
			expected: "output-go.spdx",
		},
		{
			name:     "json format",
			input:    "output.json",
			lang:     "python",
			expected: "output-python.json",
		},
		{
			name:     "double extension",
			input:    "output.spdx.json",
			lang:     "rust",
			expected: "output-rust.spdx.json",
		},
		{
			name:     "no extension",
			input:    "output",
			lang:     "node",
			expected: "output-node",
		},
		{
			name:     "path with directory",
			input:    "/tmp/sbom/output.spdx",
			lang:     "go",
			expected: "/tmp/sbom/output-go.spdx",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := buildSplitOutputFile(tc.input, tc.lang)
			require.Equal(t, tc.expected, result)
		})
	}
}

func TestValidateMultiLangMode(t *testing.T) {
	// Valid modes should not error
	opts := &generateOptions{
		directories:   []string{"."},
		format:        spdx.FormatTagValue,
		multiLangMode: spdx.MultiLangMerged,
	}
	require.NoError(t, opts.Validate())

	opts.multiLangMode = spdx.MultiLangSplit
	require.NoError(t, opts.Validate())

	// Invalid mode should error
	opts.multiLangMode = "invalid"
	require.Error(t, opts.Validate())
}

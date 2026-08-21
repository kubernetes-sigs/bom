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

package generate

import (
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"
)

const apache2 = "Apache-2.0"

func licensedNode(name, license string) *sbom.Node {
	node := &sbom.Node{Id: name, Type: sbom.Node_FILE, Name: name, FileName: name}
	if license != "" {
		node.Licenses = []string{license}
		node.LicenseConcluded = license
	}
	return node
}

func TestTopLicenseTag(t *testing.T) {
	for _, tc := range []struct {
		name     string
		nodes    []*sbom.Node
		expected string
	}{
		{
			// A classified root LICENSE wins over anything deeper.
			name: "root license",
			nodes: []*sbom.Node{
				licensedNode("LICENSE", apache2),
				licensedNode("vendor/dep/LICENSE", "MIT"),
			},
			expected: apache2,
		},
		{
			// Candidates are tried in the legacy order: an existing
			// LICENSE outranks COPYING even when listed later.
			name: "candidate priority",
			nodes: []*sbom.Node{
				licensedNode("COPYING", "GPL-2.0"),
				licensedNode("LICENSE", apache2),
			},
			expected: apache2,
		},
		{
			// An unclassifiable root candidate sends the search into
			// the tree instead of the next root candidate.
			name: "unclassified root falls back to tree",
			nodes: []*sbom.Node{
				licensedNode("LICENSE", ""),
				licensedNode("COPYING", "GPL-2.0"),
				licensedNode("docs/LICENSE.md", "MIT"),
			},
			expected: "MIT",
		},
		{
			// In the tree search the shallowest license file wins,
			// and Go sources never count as license files.
			name: "tree search depth",
			nodes: []*sbom.Node{
				licensedNode("license.go", "BSD-2-Clause"),
				licensedNode("a/b/LICENSE.txt", "MIT"),
				licensedNode("sub/LICENSE.md", apache2),
			},
			expected: apache2,
		},
		{
			name: "nothing found",
			nodes: []*sbom.Node{
				licensedNode("main.go", ""),
				licensedNode("README.md", ""),
			},
			expected: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nl := &sbom.NodeList{Nodes: tc.nodes}
			require.Equal(t, tc.expected, topLicenseTag(nl))
		})
	}
}

func TestConcludeLicenses(t *testing.T) {
	licensed := licensedNode("LICENSE", apache2)
	plain := licensedNode("README.md", "")
	nl := &sbom.NodeList{Nodes: []*sbom.Node{licensed, plain}}

	require.Equal(t, apache2, concludeLicenses(nl))

	require.Equal(t, []string{apache2}, licensed.GetLicenses())
	require.Equal(t, apache2, licensed.GetLicenseConcluded())

	require.Equal(t, []string{spdxNone}, plain.GetLicenses(),
		"scanned files without a license assert NONE")
	require.Equal(t, apache2, plain.GetLicenseConcluded(),
		"the directory license is concluded for its files")
}

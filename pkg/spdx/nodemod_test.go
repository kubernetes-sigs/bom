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

package spdx

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNodeToSPDXPackage(t *testing.T) {
	for _, tc := range []struct {
		name        string
		pkg         NodePackage
		shouldError bool
		checkDL     string // substring to check in DownloadLocation
	}{
		{
			name:    "unscoped package",
			pkg:     NodePackage{Name: "express", Version: "4.18.2"},
			checkDL: "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
		},
		{
			name:    "scoped package",
			pkg:     NodePackage{Name: "@types/node", Version: "18.11.9"},
			checkDL: "https://registry.npmjs.org/@types/node/-/node-18.11.9.tgz",
		},
		{
			name: "package with no version",
			pkg:  NodePackage{Name: "lodash", Version: ""},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spdxPackage, err := tc.pkg.ToSPDXPackage()
			if tc.shouldError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.pkg.Name, spdxPackage.Name)
			require.Equal(t, tc.pkg.Version, spdxPackage.Version)
			if tc.checkDL != "" {
				require.Equal(t, tc.checkDL, spdxPackage.DownloadLocation)
			}
		})
	}
}

func TestNodePackageURL(t *testing.T) {
	for _, tc := range []struct {
		name     string
		pkg      NodePackage
		expected string
	}{
		{
			name:     "unscoped package",
			pkg:      NodePackage{Name: "express", Version: "4.18.2"},
			expected: "pkg:npm/express@4.18.2",
		},
		{
			name:     "scoped package",
			pkg:      NodePackage{Name: "@types/node", Version: "18.11.9"},
			expected: "pkg:npm/%40types/node@18.11.9",
		},
		{
			name:     "no name",
			pkg:      NodePackage{Name: "", Version: "1.0.0"},
			expected: "",
		},
		{
			name:     "no version",
			pkg:      NodePackage{Name: "lodash", Version: ""},
			expected: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, tc.pkg.PackageURL())
		})
	}
}

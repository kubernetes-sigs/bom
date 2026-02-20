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

func TestRustToSPDXPackage(t *testing.T) {
	for _, tc := range []struct {
		pkg         RustPackage
		shouldError bool
	}{
		// Valid package
		{RustPackage{Name: "serde", Version: "1.0.152"}, false},
		// Package with no version
		{RustPackage{Name: "tokio", Version: ""}, false},
	} {
		spdxPackage, err := tc.pkg.ToSPDXPackage()
		if tc.shouldError {
			require.Error(t, err)
			continue
		}

		require.NoError(t, err)
		require.Equal(t, tc.pkg.Name, spdxPackage.Name)
		require.Equal(t, tc.pkg.Version, spdxPackage.Version)
		require.Contains(t, spdxPackage.DownloadLocation, "https://crates.io/api/v1/crates/")
	}
}

func TestRustPackageURL(t *testing.T) {
	for _, tc := range []struct {
		pkg      RustPackage
		expected string
	}{
		// Valid package
		{RustPackage{Name: "serde", Version: "1.0.152"}, "pkg:cargo/serde@1.0.152"},
		// No name
		{RustPackage{Name: "", Version: "1.0.0"}, ""},
		// No version
		{RustPackage{Name: "tokio", Version: ""}, ""},
	} {
		require.Equal(t, tc.expected, tc.pkg.PackageURL())
	}
}

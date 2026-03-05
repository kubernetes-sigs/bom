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

func TestPythonToSPDXPackage(t *testing.T) {
	for _, tc := range []struct {
		pkg         PythonPackage
		shouldError bool
	}{
		// Valid package
		{PythonPackage{Name: "requests", Version: "2.28.1"}, false},
		// Package with no name should error
		{PythonPackage{Name: "", Version: "1.0.0"}, true},
		// Package with no version is ok (version is optional for SPDX)
		{PythonPackage{Name: "flask", Version: ""}, false},
	} {
		spdxPackage, err := tc.pkg.ToSPDXPackage()
		if tc.shouldError {
			require.Error(t, err)
			continue
		}

		require.NoError(t, err)
		require.Equal(t, tc.pkg.Name, spdxPackage.Name)
		require.Equal(t, tc.pkg.Version, spdxPackage.Version)
		require.Contains(t, spdxPackage.DownloadLocation, "https://pypi.org/project/")
	}
}

func TestPythonPackageURL(t *testing.T) {
	for _, tc := range []struct {
		pkg      PythonPackage
		expected string
	}{
		// Valid package
		{PythonPackage{Name: "requests", Version: "2.28.1"}, "pkg:pypi/requests@2.28.1"},
		// No name
		{PythonPackage{Name: "", Version: "1.0.0"}, ""},
		// No version
		{PythonPackage{Name: "flask", Version: ""}, ""},
	} {
		require.Equal(t, tc.expected, tc.pkg.PackageURL())
	}
}

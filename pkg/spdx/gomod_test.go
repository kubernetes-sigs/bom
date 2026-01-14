/*
Copyright 2022 The Kubernetes Authors.

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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestToSPDXPackage(t *testing.T) {
	for _, tc := range []struct {
		pkg         GoPackage
		shouldError bool
	}{
		// No error
		{GoPackage{ImportPath: "golang.org/x/term", Revision: "v0.0.0-20220411215600-e5f449aeb171"}, false},
		// Invalid import path
		{GoPackage{ImportPath: "package/name", Revision: "v1.0.0"}, true},
		// No import path
		{GoPackage{ImportPath: "github.com/docker/cli", Revision: "v20.10.12+incompatible"}, false},
	} {
		spdxPackage, err := tc.pkg.ToSPDXPackage()
		if tc.shouldError {
			require.Error(t, err)
			continue
		}

		require.NoError(t, err)
		require.Equal(t, tc.pkg.ImportPath, spdxPackage.Name)
		require.Equal(t, strings.TrimSuffix(tc.pkg.Revision, "+incompatible"), spdxPackage.Version)
		// All versions (including +incompatible) use proxy URLs
		require.Contains(t, spdxPackage.DownloadLocation, "https://proxy.golang.org/")
	}
}

func TestPackageURL(t *testing.T) {
	for _, tc := range []struct {
		pkg      GoPackage
		expected string
	}{
		// No error
		{GoPackage{ImportPath: "package/name", Revision: "v1.0.0"}, "pkg:golang/package/name@v1.0.0"},
		// No import path
		{GoPackage{ImportPath: "", Revision: "v1.0.0"}, ""},
		// Incomplete import path
		{GoPackage{ImportPath: "package", Revision: "v1.0.0"}, ""},
		// No revision
		{GoPackage{ImportPath: "package/name", Revision: ""}, ""},
		// Check namespace
		{GoPackage{ImportPath: "github.com/jbenet/go-context", Revision: "v0.0.1"}, "pkg:golang/github.com/jbenet/go-context@v0.0.1"},
	} {
		require.Equal(t, tc.expected, tc.pkg.PackageURL())
	}
}

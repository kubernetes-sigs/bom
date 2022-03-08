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
	"testing"

	"github.com/stretchr/testify/require"
)

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
	} {
		require.Equal(t, tc.expected, tc.pkg.PackageURL())
	}
}

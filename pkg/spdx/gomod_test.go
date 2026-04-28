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
	"os"
	"path/filepath"
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

func TestPackageFromDirectory_UsesGoModModulePath(t *testing.T) {
	// Create a temporary directory structure with a go.mod at a nested path
	dir := t.TempDir()
	// Simulate extraction where files are under a subdir
	sub := filepath.Join(dir, "submodule")
	require.NoError(t, os.MkdirAll(sub, 0o755))
	// Write go.mod with module directive
	gomod := "module example.com/my/module\n"
	require.NoError(t, os.WriteFile(filepath.Join(sub, "go.mod"), []byte(gomod), 0o600))

	// Create a dummy file so PackageFromDirectory has something to scan
	require.NoError(t, os.WriteFile(filepath.Join(sub, "main.go"), []byte("package main"), 0o600))

	// Call PackageFromDirectory on the parent dir; implementation should
	// discover go.mod in scanned file tree and use module path.
	di := &spdxDefaultImplementation{}
	opts := &Options{IgnorePatterns: []string{}}
	pkg, err := di.PackageFromDirectory(opts, dir)
	require.NoError(t, err)
	require.NotNil(t, pkg)
	require.Equal(t, "example.com/my/module", pkg.Name)
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

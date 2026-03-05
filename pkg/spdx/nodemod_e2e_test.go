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
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNodeBuildPackageListFromFile tests the fallback path that parses
// package.json directly without needing npm installed.
func TestNodeBuildPackageListFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	packageJSON := `{
  "name": "test-project",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.2",
    "lodash": "~4.17.21"
  },
  "devDependencies": {
    "@types/node": ">=18.11.9",
    "typescript": "5.0.4"
  }
}`
	err := os.WriteFile(filepath.Join(tmpDir, NodePackageFile), []byte(packageJSON), 0o600)
	require.NoError(t, err)

	impl := &NodeModDefaultImpl{}
	pkgs, err := impl.buildPackageListFromFile(tmpDir)
	require.NoError(t, err)
	require.Len(t, pkgs, 4)

	// Build a map for easier verification
	pkgMap := map[string]string{}
	for _, pkg := range pkgs {
		pkgMap[pkg.Name] = pkg.Version
	}

	// Versions should have prefixes stripped
	require.Equal(t, "4.18.2", pkgMap["express"])
	require.Equal(t, "4.17.21", pkgMap["lodash"])
	require.Equal(t, "18.11.9", pkgMap["@types/node"])
	require.Equal(t, "5.0.4", pkgMap["typescript"])
}

// TestNodeBuildPackageListFallback tests that BuildPackageList falls back
// to package.json when npm is not available.
func TestNodeBuildPackageListFallback(t *testing.T) {
	tmpDir := t.TempDir()
	packageJSON := `{
  "name": "test",
  "dependencies": {
    "express": "4.18.2"
  }
}`
	err := os.WriteFile(filepath.Join(tmpDir, NodePackageFile), []byte(packageJSON), 0o600)
	require.NoError(t, err)

	// Remove npm from PATH
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir())
	defer os.Setenv("PATH", origPath)

	impl := &NodeModDefaultImpl{}
	pkgs, err := impl.BuildPackageList(tmpDir)
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	require.Equal(t, "express", pkgs[0].Name)
	require.Equal(t, "4.18.2", pkgs[0].Version)
}

// TestNodeModuleOpenAndConvert tests the full flow: create a fixture
// directory, open the module, and convert to SPDX packages.
func TestNodeModuleOpenAndConvert(t *testing.T) {
	tmpDir := t.TempDir()
	packageJSON := `{
  "name": "test-project",
  "version": "1.0.0",
  "dependencies": {
    "express": "4.18.2",
    "@types/node": "18.11.9"
  }
}`
	err := os.WriteFile(filepath.Join(tmpDir, NodePackageFile), []byte(packageJSON), 0o600)
	require.NoError(t, err)

	// Use empty PATH to force fallback
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir())
	defer os.Setenv("PATH", origPath)

	mod, err := NewNodeModuleFromPath(tmpDir)
	require.NoError(t, err)
	require.NoError(t, mod.Open())
	require.Len(t, mod.Packages, 2)

	for _, nodePkg := range mod.Packages {
		spdxPkg, err := nodePkg.ToSPDXPackage()
		require.NoError(t, err)
		require.NotEmpty(t, spdxPkg.Name)
		require.NotEmpty(t, spdxPkg.Version)
		require.Contains(t, spdxPkg.DownloadLocation, "https://registry.npmjs.org/")
		require.NotEmpty(t, spdxPkg.ID)

		// Verify purl
		require.NotEmpty(t, spdxPkg.ExternalRefs)
		found := false
		for _, ref := range spdxPkg.ExternalRefs {
			if ref.Type == "purl" {
				require.Contains(t, ref.Locator, "pkg:npm/")
				found = true
			}
		}
		require.True(t, found, "expected purl external ref for %s", nodePkg.Name)
	}
}

// TestNodeScopedPackageDownloadURL verifies that scoped packages produce
// correct npm download URLs.
func TestNodeScopedPackageDownloadURL(t *testing.T) {
	pkg := &NodePackage{Name: "@babel/core", Version: "7.20.12"}
	spdxPkg, err := pkg.ToSPDXPackage()
	require.NoError(t, err)
	require.Equal(t,
		"https://registry.npmjs.org/@babel/core/-/core-7.20.12.tgz",
		spdxPkg.DownloadLocation,
	)
}

// TestNodeDetectionInPackageFromDirectory tests that PackageFromDirectory
// detects package.json and processes it.
func TestNodeDetectionInPackageFromDirectory(t *testing.T) { //nolint:dupl // test structure mirrors python test but tests different language
	tmpDir := t.TempDir()
	packageJSON := `{
  "name": "e2e-test",
  "dependencies": {
    "lodash": "4.17.21"
  }
}`
	err := os.WriteFile(filepath.Join(tmpDir, NodePackageFile), []byte(packageJSON), 0o600)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tmpDir, "index.js"), []byte("console.log('hi')"), 0o600)
	require.NoError(t, err)

	// Use empty PATH to force fallback
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir())
	defer os.Setenv("PATH", origPath)

	sut := NewSPDX()
	sut.Options().ProcessGoModules = false
	sut.Options().ProcessPythonModules = false
	sut.Options().ProcessRustModules = false
	sut.Options().ProcessNodeModules = true
	sut.Options().ScanLicenses = false

	pkg, err := sut.PackageFromDirectory(tmpDir)
	require.NoError(t, err)
	require.NotNil(t, pkg)

	// Should have a DEPENDS_ON relationship for lodash
	rels := *pkg.GetRelationships()
	foundLodash := false
	for _, rel := range rels {
		if rel.Type == DEPENDS_ON && rel.Peer != nil && rel.Peer.GetName() == "lodash" {
			foundLodash = true
		}
	}
	require.True(t, foundLodash, "expected DEPENDS_ON relationship for lodash")
}

// TestNodeBuildPackageListWithNpm tests the npm path when npm is available.
func TestNodeBuildPackageListWithNpm(t *testing.T) {
	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("npm not available, skipping npm-based test")
	}

	// Create a minimal node project and install a dependency
	tmpDir := t.TempDir()
	packageJSON := `{
  "name": "e2e-npm-test",
  "version": "1.0.0",
  "dependencies": {}
}`
	err := os.WriteFile(filepath.Join(tmpDir, NodePackageFile), []byte(packageJSON), 0o600)
	require.NoError(t, err)

	impl := &NodeModDefaultImpl{}
	pkgs, err := impl.BuildPackageList(tmpDir)
	require.NoError(t, err)
	// A project with no deps should return an empty list.
	// The main point is that npm ls runs without error.
	require.Empty(t, pkgs, "project with no dependencies should produce an empty package list")
}

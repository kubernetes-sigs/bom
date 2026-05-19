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

// requireCargo skips the test when cargo is not available.
func requireCargo(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo not available, skipping cargo-based test")
	}
}

// writeMinimalCargoProject creates a minimal Cargo project in dir so that
// `cargo metadata` can succeed. The project depends on a single small crate.
func writeMinimalCargoProject(t *testing.T, dir string) {
	t.Helper()

	cargoToml := `[package]
name = "bom-e2e-test"
version = "0.1.0"
edition = "2021"

[dependencies]
itoa = "1.0"
`
	err := os.WriteFile(filepath.Join(dir, RustCargoFile), []byte(cargoToml), 0o600)
	require.NoError(t, err)

	// cargo metadata needs a src/main.rs to be happy
	srcDir := filepath.Join(dir, "src")
	require.NoError(t, os.MkdirAll(srcDir, 0o755))
	err = os.WriteFile(filepath.Join(srcDir, "main.rs"), []byte("fn main() {}\n"), 0o600)
	require.NoError(t, err)
}

// TestRustBuildPackageListWithCargo verifies that BuildPackageList runs
// cargo metadata and returns packages.
func TestRustBuildPackageListWithCargo(t *testing.T) {
	requireCargo(t)

	tmpDir := t.TempDir()
	writeMinimalCargoProject(t, tmpDir)

	impl := &RustModDefaultImpl{}
	pkgs, err := impl.BuildPackageList(tmpDir)
	require.NoError(t, err)
	require.NotEmpty(t, pkgs, "should find at least one dependency (itoa)")

	// Verify itoa is in the list
	foundItoa := false
	for _, pkg := range pkgs {
		require.NotEmpty(t, pkg.Name)
		require.NotEmpty(t, pkg.Version)
		if pkg.Name == "itoa" {
			foundItoa = true
		}
	}
	require.True(t, foundItoa, "expected to find itoa in Rust dependencies")
}

// TestRustBuildPackageListNoCargo verifies that BuildPackageList returns
// an error when cargo is not on PATH.
func TestRustBuildPackageListNoCargo(t *testing.T) {
	tmpDir := t.TempDir()
	writeMinimalCargoProject(t, tmpDir)

	// Remove cargo from PATH
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir())
	defer os.Setenv("PATH", origPath)

	impl := &RustModDefaultImpl{}
	_, err := impl.BuildPackageList(tmpDir)
	require.Error(t, err, "should fail when cargo is not available")
	require.Contains(t, err.Error(), "cargo executable not found")
}

// TestRustModuleOpenAndConvert tests the full flow: create a fixture
// project, open the module, and convert packages to SPDX packages.
func TestRustModuleOpenAndConvert(t *testing.T) {
	requireCargo(t)

	tmpDir := t.TempDir()
	writeMinimalCargoProject(t, tmpDir)

	mod, err := NewRustModuleFromPath(tmpDir)
	require.NoError(t, err)
	require.NoError(t, mod.Open())
	require.NotEmpty(t, mod.Packages, "should have at least one package")

	for _, rustPkg := range mod.Packages {
		spdxPkg, err := rustPkg.ToSPDXPackage()
		require.NoError(t, err)
		require.NotEmpty(t, spdxPkg.Name)
		require.NotEmpty(t, spdxPkg.Version)
		require.Contains(t, spdxPkg.DownloadLocation, "https://crates.io/api/v1/crates/")
		require.NotEmpty(t, spdxPkg.ID, "SPDX ID should be set")

		// Verify purl external ref
		require.NotEmpty(t, spdxPkg.ExternalRefs)
		found := false
		for _, ref := range spdxPkg.ExternalRefs {
			if ref.Type == "purl" {
				require.Contains(t, ref.Locator, "pkg:cargo/")
				found = true
			}
		}
		require.True(t, found, "expected purl external ref for %s", rustPkg.Name)
	}
}

// TestRustDetectionInPackageFromDirectory tests that PackageFromDirectory
// detects Cargo.toml and processes it when cargo is available.
func TestRustDetectionInPackageFromDirectory(t *testing.T) {
	requireCargo(t)

	tmpDir := t.TempDir()
	writeMinimalCargoProject(t, tmpDir)

	sut := NewSPDX()
	sut.Options().ProcessGoModules = false
	sut.Options().ProcessPythonModules = false
	sut.Options().ProcessNodeModules = false
	sut.Options().ProcessRustModules = true
	sut.Options().ScanLicenses = false

	pkg, err := sut.PackageFromDirectory(tmpDir)
	require.NoError(t, err)
	require.NotNil(t, pkg)

	// Should have at least one DEPENDS_ON relationship for itoa
	rels := *pkg.GetRelationships()
	foundItoa := false
	for _, rel := range rels {
		if rel.Type == DEPENDS_ON && rel.Peer != nil && rel.Peer.GetName() == "itoa" {
			foundItoa = true
		}
	}
	require.True(t, foundItoa, "expected DEPENDS_ON relationship for itoa package")
}

// TestRustPackageRemoveDownloads verifies cleanup of downloaded packages.
func TestRustPackageRemoveDownloads(t *testing.T) {
	// Create a fake downloaded package directory
	tmpDir := t.TempDir()
	fakeLocalDir := filepath.Join(tmpDir, "itoa-download")
	require.NoError(t, os.MkdirAll(fakeLocalDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(fakeLocalDir, "Cargo.toml"), []byte("[package]"), 0o600))

	pkgs := []*RustPackage{
		{Name: "itoa", Version: "1.0.0", LocalDir: fakeLocalDir, TmpDir: true},
		{Name: "serde", Version: "1.0.0", LocalDir: "", TmpDir: false}, // no local dir, should be a no-op
	}

	impl := &RustModDefaultImpl{}
	require.NoError(t, impl.RemoveDownloads(pkgs))

	// fakeLocalDir should have been cleaned up
	_, err := os.Stat(fakeLocalDir)
	require.True(t, os.IsNotExist(err), "expected download directory to be removed")
}

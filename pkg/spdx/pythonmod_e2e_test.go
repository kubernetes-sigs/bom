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

// TestPythonBuildPackageListFromRequirements tests the fallback path that
// parses requirements.txt directly without needing pip installed.
func TestPythonBuildPackageListFromRequirements(t *testing.T) {
	// Create temp directory with a requirements.txt
	tmpDir := t.TempDir()
	reqContent := `# This is a comment
requests==2.28.1
flask==2.2.2
numpy==1.23.5

# Inline comments and flags should be skipped
-r other-requirements.txt
gunicorn==20.1.0
`
	err := os.WriteFile(filepath.Join(tmpDir, PythonRequirementsFile), []byte(reqContent), 0o600)
	require.NoError(t, err)

	impl := &PythonModDefaultImpl{}
	pkgs, err := impl.parseRequirementsFile(filepath.Join(tmpDir, PythonRequirementsFile))
	require.NoError(t, err)
	require.Len(t, pkgs, 4)

	// Verify the parsed packages
	expected := map[string]string{
		"requests": "2.28.1",
		"flask":    "2.2.2",
		"numpy":    "1.23.5",
		"gunicorn": "20.1.0",
	}
	for _, pkg := range pkgs {
		ver, ok := expected[pkg.Name]
		require.True(t, ok, "unexpected package: %s", pkg.Name)
		require.Equal(t, ver, pkg.Version)
	}
}

// TestPythonBuildPackageListFallback tests that BuildPackageList falls back
// to requirements.txt parsing when pip is not available (or fails).
func TestPythonBuildPackageListFallback(t *testing.T) {
	tmpDir := t.TempDir()
	reqContent := `django==4.1.4
celery==5.2.7
`
	err := os.WriteFile(filepath.Join(tmpDir, PythonRequirementsFile), []byte(reqContent), 0o600)
	require.NoError(t, err)

	// Simulate pip not being available by using a PATH with no pip
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir()) // empty dir, no pip binary
	defer os.Setenv("PATH", origPath)

	impl := &PythonModDefaultImpl{}
	pkgs, err := impl.BuildPackageList(tmpDir)
	require.NoError(t, err)
	require.Len(t, pkgs, 2)
	require.Equal(t, "django", pkgs[0].Name)
	require.Equal(t, "4.1.4", pkgs[0].Version)
	require.Equal(t, "celery", pkgs[1].Name)
	require.Equal(t, "5.2.7", pkgs[1].Version)
}

// TestPythonModuleOpenAndConvert tests the full flow: create a fixture
// directory, open the module, and convert all packages to SPDX packages.
func TestPythonModuleOpenAndConvert(t *testing.T) {
	tmpDir := t.TempDir()
	reqContent := `requests==2.28.1
flask==2.2.2
`
	err := os.WriteFile(filepath.Join(tmpDir, PythonRequirementsFile), []byte(reqContent), 0o600)
	require.NoError(t, err)

	// Use empty PATH to force fallback to requirements.txt parsing
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir())
	defer os.Setenv("PATH", origPath)

	mod, err := NewPythonModuleFromPath(tmpDir)
	require.NoError(t, err)
	require.NoError(t, mod.Open())
	require.Len(t, mod.Packages, 2)

	// Convert to SPDX packages
	for _, pyPkg := range mod.Packages {
		spdxPkg, err := pyPkg.ToSPDXPackage()
		require.NoError(t, err)
		require.NotEmpty(t, spdxPkg.Name)
		require.NotEmpty(t, spdxPkg.Version)
		require.Contains(t, spdxPkg.DownloadLocation, "https://pypi.org/project/")
		require.NotEmpty(t, spdxPkg.ID, "SPDX ID should be set")

		// Verify purl external ref
		require.NotEmpty(t, spdxPkg.ExternalRefs)
		found := false
		for _, ref := range spdxPkg.ExternalRefs {
			if ref.Type == "purl" {
				require.Contains(t, ref.Locator, "pkg:pypi/")
				found = true
			}
		}
		require.True(t, found, "expected purl external ref")
	}
}

// TestPythonDetectionInPackageFromDirectory tests that PackageFromDirectory
// detects Python manifests and processes them.
func TestPythonDetectionInPackageFromDirectory(t *testing.T) { //nolint:dupl // test structure mirrors node test but tests different language
	tmpDir := t.TempDir()
	reqContent := `requests==2.28.1
`
	err := os.WriteFile(filepath.Join(tmpDir, PythonRequirementsFile), []byte(reqContent), 0o600)
	require.NoError(t, err)

	// Also need at least one file in the dir for PackageFromDirectory to work
	err = os.WriteFile(filepath.Join(tmpDir, "main.py"), []byte("print('hello')"), 0o600)
	require.NoError(t, err)

	// Use empty PATH to force fallback parsing
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir())
	defer os.Setenv("PATH", origPath)

	sut := NewSPDX()
	sut.Options().ProcessGoModules = false
	sut.Options().ProcessNodeModules = false
	sut.Options().ProcessRustModules = false
	sut.Options().ProcessPythonModules = true
	sut.Options().ScanLicenses = false

	pkg, err := sut.PackageFromDirectory(tmpDir)
	require.NoError(t, err)
	require.NotNil(t, pkg)

	// Should have at least one DEPENDS_ON relationship for requests
	rels := *pkg.GetRelationships()
	foundRequests := false
	for _, rel := range rels {
		if rel.Type == DEPENDS_ON && rel.Peer != nil && rel.Peer.GetName() == "requests" {
			foundRequests = true
		}
	}
	require.True(t, foundRequests, "expected DEPENDS_ON relationship for requests package")
}

// TestPythonManifestDetection tests hasPythonManifest with various files.
func TestPythonManifestDetection(t *testing.T) {
	for _, tc := range []struct {
		name     string
		files    []string
		expected bool
	}{
		{"requirements.txt", []string{PythonRequirementsFile}, true},
		{"setup.py", []string{PythonSetupFile}, true},
		{"pyproject.toml", []string{PythonPyprojectFile}, true},
		{"Pipfile", []string{PythonPipfile}, true},
		{"no python files", []string{"main.go"}, false},
		{"empty directory", []string{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			for _, f := range tc.files {
				err := os.WriteFile(filepath.Join(tmpDir, f), []byte(""), 0o600)
				require.NoError(t, err)
			}
			require.Equal(t, tc.expected, hasPythonManifest(tmpDir))
		})
	}
}

// TestPythonBuildPackageListWithPip tests the pip path when pip is available.
func TestPythonBuildPackageListWithPip(t *testing.T) {
	if _, err := exec.LookPath("pip"); err != nil {
		if _, err := exec.LookPath("pip3"); err != nil {
			t.Skip("pip/pip3 not available, skipping pip-based test")
		}
	}

	// pip list --format=json lists currently installed packages.
	// We just verify it returns something without error.
	impl := &PythonModDefaultImpl{}

	// Use current directory (which likely has no requirements.txt but pip should still work)
	cwd, err := os.Getwd()
	require.NoError(t, err)

	pipBin, err := exec.LookPath("pip")
	if err != nil {
		pipBin, err = exec.LookPath("pip3")
		require.NoError(t, err, "neither pip nor pip3 found in PATH")
	}

	pkgs, err := impl.buildPackageListFromPip(pipBin, cwd)
	require.NoError(t, err)
	// pip list should return at least pip itself
	require.NotEmpty(t, pkgs, "pip list should return at least one package")

	// Verify structure
	for _, pkg := range pkgs {
		require.NotEmpty(t, pkg.Name)
		require.NotEmpty(t, pkg.Version)
	}
}

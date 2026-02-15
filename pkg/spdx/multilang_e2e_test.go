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
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMultiLangMergedDetection tests that a directory containing both Python
// and Node.js manifest files has dependencies from both languages merged into
// a single Package when all language scanners are enabled.
func TestMultiLangMergedDetection(t *testing.T) {
	tmpDir := t.TempDir()

	// Write a Python requirements.txt
	reqContent := `requests==2.28.1
flask==2.2.2
`
	err := os.WriteFile(filepath.Join(tmpDir, PythonRequirementsFile), []byte(reqContent), 0o600)
	require.NoError(t, err)

	// Write a Node package.json
	packageJSON := `{
  "name": "multi-lang-test",
  "version": "1.0.0",
  "dependencies": {
    "express": "4.18.2",
    "lodash": "4.17.21"
  }
}`
	err = os.WriteFile(filepath.Join(tmpDir, NodePackageFile), []byte(packageJSON), 0o600)
	require.NoError(t, err)

	// Need at least one regular file for PackageFromDirectory
	err = os.WriteFile(filepath.Join(tmpDir, "README.md"), []byte("# Multi-lang project\n"), 0o600)
	require.NoError(t, err)

	// Use empty PATH to force fallback parsing for both languages
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir())
	defer os.Setenv("PATH", origPath)

	sut := NewSPDX()
	sut.Options().ProcessGoModules = false
	sut.Options().ProcessPythonModules = true
	sut.Options().ProcessNodeModules = true
	sut.Options().ProcessRustModules = false
	sut.Options().ScanLicenses = false

	pkg, err := sut.PackageFromDirectory(tmpDir)
	require.NoError(t, err)
	require.NotNil(t, pkg)

	// Collect all DEPENDS_ON peer names
	rels := *pkg.GetRelationships()
	depNames := map[string]bool{}
	for _, rel := range rels {
		if rel.Type == DEPENDS_ON && rel.Peer != nil {
			depNames[rel.Peer.GetName()] = true
		}
	}

	// Verify Python deps are present
	require.True(t, depNames["requests"], "expected Python dependency 'requests'")
	require.True(t, depNames["flask"], "expected Python dependency 'flask'")

	// Verify Node deps are present
	require.True(t, depNames["express"], "expected Node dependency 'express'")
	require.True(t, depNames["lodash"], "expected Node dependency 'lodash'")

	// Should have at least 4 DEPENDS_ON relationships
	depCount := 0
	for _, rel := range rels {
		if rel.Type == DEPENDS_ON {
			depCount++
		}
	}
	require.GreaterOrEqual(t, depCount, 4, "expected at least 4 dependency relationships")
}

// TestMultiLangSelectiveDisable tests that disabling a language scanner
// prevents its dependencies from appearing in the output even when its
// manifest file is present.
func TestMultiLangSelectiveDisable(t *testing.T) {
	tmpDir := t.TempDir()

	// Write both manifests
	err := os.WriteFile(filepath.Join(tmpDir, PythonRequirementsFile), []byte("requests==2.28.1\n"), 0o600)
	require.NoError(t, err)
	packageJSON := `{"name":"test","dependencies":{"lodash":"4.17.21"}}`
	err = os.WriteFile(filepath.Join(tmpDir, NodePackageFile), []byte(packageJSON), 0o600)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tmpDir, "app.py"), []byte("pass\n"), 0o600)
	require.NoError(t, err)

	// Use empty PATH
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir())
	defer os.Setenv("PATH", origPath)

	// Enable Python, disable Node
	sut := NewSPDX()
	sut.Options().ProcessGoModules = false
	sut.Options().ProcessPythonModules = true
	sut.Options().ProcessNodeModules = false
	sut.Options().ProcessRustModules = false
	sut.Options().ScanLicenses = false

	pkg, err := sut.PackageFromDirectory(tmpDir)
	require.NoError(t, err)
	require.NotNil(t, pkg)

	rels := *pkg.GetRelationships()
	depNames := map[string]bool{}
	for _, rel := range rels {
		if rel.Type == DEPENDS_ON && rel.Peer != nil {
			depNames[rel.Peer.GetName()] = true
		}
	}

	// Python dep should be present
	require.True(t, depNames["requests"], "expected Python dependency 'requests'")
	// Node dep should NOT be present
	require.False(t, depNames["lodash"], "did not expect Node dependency 'lodash' when Node scanning is disabled")
}

// TestMultiLangSPDXPackageIDs verifies that packages from different languages
// get distinct SPDX IDs (no collisions).
func TestMultiLangSPDXPackageIDs(t *testing.T) {
	tmpDir := t.TempDir()

	// Write both manifests
	err := os.WriteFile(filepath.Join(tmpDir, PythonRequirementsFile), []byte("requests==2.28.1\nnumpy==1.23.5\n"), 0o600)
	require.NoError(t, err)
	packageJSON := `{"name":"test","dependencies":{"express":"4.18.2","lodash":"4.17.21"}}`
	err = os.WriteFile(filepath.Join(tmpDir, NodePackageFile), []byte(packageJSON), 0o600)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tmpDir, "main.py"), []byte("pass\n"), 0o600)
	require.NoError(t, err)

	// Use empty PATH
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir())
	defer os.Setenv("PATH", origPath)

	sut := NewSPDX()
	sut.Options().ProcessGoModules = false
	sut.Options().ProcessPythonModules = true
	sut.Options().ProcessNodeModules = true
	sut.Options().ProcessRustModules = false
	sut.Options().ScanLicenses = false

	pkg, err := sut.PackageFromDirectory(tmpDir)
	require.NoError(t, err)
	require.NotNil(t, pkg)

	// Collect all dependency SPDX IDs
	rels := *pkg.GetRelationships()
	ids := map[string]string{} // id -> name
	for _, rel := range rels {
		if rel.Type == DEPENDS_ON && rel.Peer != nil {
			id := rel.Peer.SPDXID()
			name := rel.Peer.GetName()
			if existing, ok := ids[id]; ok {
				t.Fatalf("SPDX ID collision: %q used by both %q and %q", id, existing, name)
			}
			ids[id] = name
		}
	}

	require.Len(t, ids, 4, "expected 4 unique dependency SPDX IDs")
}

// TestMultiLangNoManifests verifies that PackageFromDirectory still works
// when no language manifests are present (just files).
func TestMultiLangNoManifests(t *testing.T) {
	tmpDir := t.TempDir()

	err := os.WriteFile(filepath.Join(tmpDir, "README.md"), []byte("# Hello\n"), 0o600)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tmpDir, "data.txt"), []byte("some data\n"), 0o600)
	require.NoError(t, err)

	sut := NewSPDX()
	sut.Options().ProcessGoModules = false
	sut.Options().ProcessPythonModules = true
	sut.Options().ProcessNodeModules = true
	sut.Options().ProcessRustModules = true
	sut.Options().ScanLicenses = false

	pkg, err := sut.PackageFromDirectory(tmpDir)
	require.NoError(t, err)
	require.NotNil(t, pkg)

	// Should have no DEPENDS_ON relationships (only CONTAINS for the files)
	rels := *pkg.GetRelationships()
	for _, rel := range rels {
		require.NotEqual(t, DEPENDS_ON, rel.Type, "should not have DEPENDS_ON when no manifests present")
	}
}

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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nozzle/throttler"
	purl "github.com/package-url/packageurl-go"
	"github.com/sirupsen/logrus"

	"sigs.k8s.io/release-utils/helpers"
	"sigs.k8s.io/release-utils/http"

	"sigs.k8s.io/bom/pkg/license"
)

const (
	pythonDownloadDir      = spdxTempDir + "/python-scanner"
	PythonRequirementsFile = "requirements.txt"
	PythonSetupFile        = "setup.py"
	PythonPyprojectFile    = "pyproject.toml"
	PythonPipfile          = "Pipfile"
)

// requirementRegexp matches lines like "package==1.2.3" in requirements.txt.
var requirementRegexp = regexp.MustCompile(`^([a-zA-Z0-9_-]+)==(\S+)`)

// NewPythonModuleFromPath returns a new python module from the specified path.
func NewPythonModuleFromPath(path string) (*PythonModule, error) {
	mod := NewPythonModule()
	mod.opts.Path = path
	return mod, nil
}

// NewPythonModule creates a new PythonModule with default options and implementation.
func NewPythonModule() *PythonModule {
	return &PythonModule{
		opts: &PythonModuleOptions{},
		impl: &PythonModDefaultImpl{},
	}
}

// PythonModule abstracts the python module data of a project.
type PythonModule struct {
	impl     PythonModImplementation
	opts     *PythonModuleOptions
	Packages []*PythonPackage
}

// PythonModuleOptions are the options for the python module scanner.
type PythonModuleOptions struct {
	Path         string // Path to the dir where requirements.txt (or similar) resides
	ScanLicenses bool   // Scan licenses from every possible place unless false
}

// Options returns a pointer to the module options set.
func (mod *PythonModule) Options() *PythonModuleOptions {
	return mod.opts
}

// SetScanLicenses sets the ScanLicenses option on the module.
func (mod *PythonModule) SetScanLicenses(v bool) {
	mod.opts.ScanLicenses = v
}

// GetPackageConverters returns the module's packages as spdxPackageConverter interfaces.
func (mod *PythonModule) GetPackageConverters() []spdxPackageConverter {
	converters := make([]spdxPackageConverter, len(mod.Packages))
	for i, pkg := range mod.Packages {
		converters[i] = pkg
	}
	return converters
}

// PythonPackage contains basic package data we need.
type PythonPackage struct {
	TmpDir        bool
	Name          string
	Version       string
	LocalDir      string
	LicenseID     string
	CopyrightText string
}

// ToSPDXPackage builds an SPDX package from the python package data.
func (pkg *PythonPackage) ToSPDXPackage() (*Package, error) {
	if pkg.Name == "" {
		return nil, errors.New("python package name is empty")
	}

	downloadURL := fmt.Sprintf("https://pypi.org/project/%s/%s/", pkg.Name, pkg.Version)

	spdxPackage := NewPackage()
	spdxPackage.Options().Prefix = "pypi"
	spdxPackage.Name = pkg.Name
	spdxPackage.BuildID(pkg.Name, pkg.Version)
	spdxPackage.DownloadLocation = downloadURL
	spdxPackage.LicenseConcluded = pkg.LicenseID
	spdxPackage.Version = pkg.Version
	spdxPackage.CopyrightText = pkg.CopyrightText

	if packageurl := pkg.PackageURL(); packageurl != "" {
		spdxPackage.ExternalRefs = append(spdxPackage.ExternalRefs, ExternalRef{
			Category: CatPackageManager,
			Type:     "purl",
			Locator:  packageurl,
		})
	}
	return spdxPackage, nil
}

// PackageURL returns a purl if the python package has enough data to
// generate one. If data is missing, it will return an empty string.
func (pkg *PythonPackage) PackageURL() string {
	if pkg.Name == "" || pkg.Version == "" {
		return ""
	}

	return purl.NewPackageURL(
		purl.TypePyPi, "", pkg.Name,
		pkg.Version, nil, "",
	).ToString()
}

// PythonModImplementation is the interface that the python module
// scanner uses to interact with the system.
type PythonModImplementation interface {
	BuildPackageList(path string) ([]*PythonPackage, error)
	DownloadPackage(*PythonPackage, *PythonModuleOptions, bool) error
	RemoveDownloads([]*PythonPackage) error
	LicenseReader() (*license.Reader, error)
	ScanPackageLicense(*PythonPackage, *license.Reader, *PythonModuleOptions) error
}

// Open initializes the python module from the configured path.
func (mod *PythonModule) Open() error {
	pkgs, err := mod.impl.BuildPackageList(mod.opts.Path)
	if err != nil {
		return fmt.Errorf("building python package list: %w", err)
	}
	mod.Packages = pkgs
	return nil
}

// RemoveDownloads cleans all downloads.
func (mod *PythonModule) RemoveDownloads() error {
	return mod.impl.RemoveDownloads(mod.Packages)
}

// ScanLicenses scans the licenses and populates the fields.
func (mod *PythonModule) ScanLicenses() error {
	if mod.Packages == nil {
		return errors.New("unable to scan license files, package list is nil")
	}

	reader, err := mod.impl.LicenseReader()
	if err != nil {
		return fmt.Errorf("creating license scanner: %w", err)
	}

	logrus.Infof("Scanning licenses for %d python packages", len(mod.Packages))

	// Create a new Throttler that will get parallelDownloads urls at a time
	t := throttler.New(10, len(mod.Packages))
	for _, pkg := range mod.Packages {
		// Launch a goroutine to fetch the package contents
		go func(curPkg *PythonPackage) {
			logrus.WithField(
				"package", curPkg.Name).Debugf(
				"Downloading package (%d total)", len(mod.Packages),
			)
			defer t.Done(err)

			// Download the package to a temp location
			if curPkg.LocalDir == "" {
				// Call download with no force in case local data is missing
				if err2 := mod.impl.DownloadPackage(curPkg, mod.opts, false); err2 != nil {
					// If we're unable to download the module we don't treat it as
					// fatal, package will remain without license info but we go
					// on scanning the rest of the packages.
					logrus.WithField("package", curPkg.Name).Error(err2)
					return
				}
			}

			// Now that we are sure it's in the filesystem, scan the license
			if err = mod.impl.ScanPackageLicense(curPkg, reader, mod.opts); err != nil {
				logrus.WithField("package", curPkg.Name).Errorf(
					"scanning package %s for licensing info", curPkg.Name,
				)
			}
		}(pkg)
		t.Throttle()
	}

	if t.Err() != nil {
		return t.Err()
	}

	return nil
}

// PythonModDefaultImpl is the default implementation of PythonModImplementation.
type PythonModDefaultImpl struct {
	licenseReader *license.Reader
}

// BuildPackageList builds a list of python packages from the project at the given path.
// It first tries to use pip to list installed packages. If pip is not available,
// it falls back to parsing requirements.txt directly.
func (di *PythonModDefaultImpl) BuildPackageList(path string) ([]*PythonPackage, error) {
	pkgs := []*PythonPackage{}

	// Log what manifest files we find
	for _, f := range []string{PythonRequirementsFile, PythonSetupFile, PythonPyprojectFile, PythonPipfile} {
		if helpers.Exists(filepath.Join(path, f)) {
			logrus.Infof("Found python manifest file: %s", f)
		}
	}

	// Try pip list --format=json first
	pipBin, err := exec.LookPath("pip")
	if err != nil {
		// Also try pip3
		pipBin, err = exec.LookPath("pip3")
	}

	if err == nil {
		pkgs, err = di.buildPackageListFromPip(pipBin, path)
		if err == nil {
			logrus.Infof("Found %d packages from pip", len(pkgs))
			return pkgs, nil
		}
		logrus.Warnf("pip list failed, falling back to requirements.txt parsing: %v", err)
	} else {
		logrus.Warn("pip not found in PATH, falling back to requirements.txt parsing")
	}

	// Fallback: parse requirements.txt directly
	reqFile := filepath.Join(path, PythonRequirementsFile)
	if !helpers.Exists(reqFile) {
		return pkgs, fmt.Errorf("no %s found in %s and pip is not available", PythonRequirementsFile, path)
	}

	pkgs, err = di.parseRequirementsFile(reqFile)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", PythonRequirementsFile, err)
	}

	logrus.Infof("Found %d packages from %s", len(pkgs), PythonRequirementsFile)
	return pkgs, nil
}

// buildPackageListFromPip runs pip list --format=json and parses the output.
func (di *PythonModDefaultImpl) buildPackageListFromPip(pipBin, path string) ([]*PythonPackage, error) {
	// Check if we have a requirements file to install from
	reqFile := filepath.Join(path, PythonRequirementsFile)
	if helpers.Exists(reqFile) {
		logrus.Infof("Using pip to list packages from %s", reqFile)
	}

	cmd := exec.CommandContext(context.TODO(), pipBin, "list", "--format=json") // #nosec G204
	cmd.Dir = path
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("running pip list: %w", err)
	}

	type pipPackage struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}

	var pipPkgs []pipPackage
	if err := json.Unmarshal(output, &pipPkgs); err != nil {
		return nil, fmt.Errorf("parsing pip list output: %w", err)
	}

	pkgs := make([]*PythonPackage, 0, len(pipPkgs))
	for _, p := range pipPkgs {
		logrus.Infof(" > %s@%s", p.Name, p.Version)
		pkgs = append(pkgs, &PythonPackage{
			Name:    p.Name,
			Version: p.Version,
		})
	}
	return pkgs, nil
}

// parseRequirementsFile reads a requirements.txt and extracts pinned dependencies.
func (di *PythonModDefaultImpl) parseRequirementsFile(reqFile string) ([]*PythonPackage, error) {
	data, err := os.ReadFile(reqFile)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", reqFile, err)
	}

	pkgs := []*PythonPackage{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		matches := requirementRegexp.FindStringSubmatch(line)
		if len(matches) == 3 {
			logrus.Infof(" > %s@%s", matches[1], matches[2])
			pkgs = append(pkgs, &PythonPackage{
				Name:    matches[1],
				Version: matches[2],
			})
		}
	}
	return pkgs, nil
}

// DownloadPackage downloads a python package source from PyPI and extracts it
// to a temporary directory. It sets pkg.LocalDir to the extracted location.
func (di *PythonModDefaultImpl) DownloadPackage(pkg *PythonPackage, _ *PythonModuleOptions, force bool) error {
	if pkg.LocalDir != "" && helpers.Exists(pkg.LocalDir) && !force {
		logrus.WithField("package", pkg.Name).Infof("Not downloading %s as it already has local data", pkg.Name)
		return nil
	}

	logrus.WithField("package", pkg.Name).Debugf("Downloading package %s@%s", pkg.Name, pkg.Version)

	// Create temp directory
	if !helpers.Exists(filepath.Join(os.TempDir(), pythonDownloadDir)) {
		if err := os.MkdirAll(
			filepath.Join(os.TempDir(), pythonDownloadDir), os.FileMode(0o755),
		); err != nil {
			return fmt.Errorf("creating parent tmpdir: %w", err)
		}
	}

	tmpDir, err := os.MkdirTemp(filepath.Join(os.TempDir(), pythonDownloadDir), "package-download-")
	if err != nil {
		return fmt.Errorf("creating temporary dir: %w", err)
	}

	// Query the PyPI JSON API to find the sdist download URL
	pypiURL := fmt.Sprintf("https://pypi.org/pypi/%s/%s/json", pkg.Name, pkg.Version)
	agent := http.NewAgent()
	data, err := agent.Get(pypiURL)
	if err != nil {
		return fmt.Errorf("querying PyPI API for %s@%s (%s): %w", pkg.Name, pkg.Version, pypiURL, err)
	}

	// Parse the PyPI API response to find sdist URL
	sdistURL, err := parsePyPIResponse(data)
	if err != nil {
		return fmt.Errorf("parsing PyPI response for %s@%s: %w", pkg.Name, pkg.Version, err)
	}

	// Download the sdist tarball
	tarballData, err := agent.Get(sdistURL)
	if err != nil {
		return fmt.Errorf("downloading sdist for %s from %s: %w", pkg.Name, sdistURL, err)
	}

	// Extract the tarball
	if err := extractTarGz(tarballData, tmpDir); err != nil {
		return fmt.Errorf("extracting sdist tarball for %s: %w", pkg.Name, err)
	}

	logrus.WithField("package", pkg.Name).Infof(
		"Python package %s (version %s) downloaded to %s", pkg.Name, pkg.Version, tmpDir,
	)
	pkg.LocalDir = tmpDir
	pkg.TmpDir = true
	return nil
}

// parsePyPIResponse parses the PyPI JSON API response and returns the sdist download URL.
func parsePyPIResponse(data []byte) (string, error) {
	var response struct {
		URLs []struct {
			PackageType string `json:"packagetype"`
			URL         string `json:"url"`
		} `json:"urls"`
	}

	if err := json.Unmarshal(data, &response); err != nil {
		return "", fmt.Errorf("unmarshaling PyPI response: %w", err)
	}

	// Look for sdist first
	for _, u := range response.URLs {
		if u.PackageType == "sdist" {
			return u.URL, nil
		}
	}

	// Fallback to any available URL
	if len(response.URLs) > 0 {
		return response.URLs[0].URL, nil
	}

	return "", errors.New("no download URL found in PyPI response")
}

// RemoveDownloads takes a list of packages and removes their downloads.
func (di *PythonModDefaultImpl) RemoveDownloads(packageList []*PythonPackage) error {
	for _, pkg := range packageList {
		if pkg.Name != "" && helpers.Exists(pkg.LocalDir) && pkg.TmpDir {
			if err := os.RemoveAll(pkg.LocalDir); err != nil {
				return fmt.Errorf("removing package data: %w", err)
			}
		}
	}
	return nil
}

// LicenseReader returns a license reader.
func (di *PythonModDefaultImpl) LicenseReader() (*license.Reader, error) {
	if di.licenseReader == nil {
		opts := license.DefaultReaderOptions
		opts.CacheDir = filepath.Join(os.TempDir(), spdxLicenseDlCache)
		opts.LicenseDir = filepath.Join(os.TempDir(), spdxLicenseData)
		if !helpers.Exists(opts.CacheDir) {
			if err := os.MkdirAll(opts.CacheDir, os.FileMode(0o755)); err != nil {
				return nil, fmt.Errorf("creating dir: %w", err)
			}
		}
		reader, err := license.NewReaderWithOptions(opts)
		if err != nil {
			return nil, fmt.Errorf("creating reader: %w", err)
		}

		di.licenseReader = reader
	}
	return di.licenseReader, nil
}

// ScanPackageLicense scans a package for licensing info.
func (di *PythonModDefaultImpl) ScanPackageLicense(
	pkg *PythonPackage, reader *license.Reader, _ *PythonModuleOptions,
) error {
	dir := pkg.LocalDir
	if dir == "" {
		return fmt.Errorf("package %s has no local directory to scan", pkg.Name)
	}

	licenseResult, err := reader.ReadTopLicense(dir)
	if err != nil {
		return fmt.Errorf("scanning package %s for licensing information: %w", pkg.Name, err)
	}

	if licenseResult != nil {
		logrus.Debugf(
			"Package %s license is %s", pkg.Name,
			licenseResult.License.LicenseID,
		)
		pkg.LicenseID = licenseResult.License.LicenseID
		pkg.CopyrightText = licenseResult.Text
	} else {
		logrus.Warnf("Could not find licensing information for package %s", pkg.Name)
	}
	return nil
}

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
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	purl "github.com/package-url/packageurl-go"
	"github.com/sirupsen/logrus"

	"sigs.k8s.io/release-utils/command"
	"sigs.k8s.io/release-utils/helpers"
	"sigs.k8s.io/release-utils/http"

	"sigs.k8s.io/bom/pkg/license"
)

const (
	rustDownloadDir   = spdxTempDir + "/rust-scanner"
	RustCargoFile     = "Cargo.toml"
	RustCargoLockFile = "Cargo.lock"

	// cratesIORegistry is the crates.io source string in cargo metadata output.
	cratesIORegistry = "registry+https://github.com/rust-lang/crates.io-index"

	// Maximum file size for tar extraction (100MB).
	maxRustExtractFileSize = 100 * 1024 * 1024
)

// NewRustModuleFromPath returns a new Rust module from the specified path.
func NewRustModuleFromPath(path string) (*RustModule, error) {
	mod := NewRustModule()
	mod.opts.Path = path
	return mod, nil
}

// NewRustModule creates a new RustModule with default options and implementation.
func NewRustModule() *RustModule {
	return &RustModule{
		opts: &RustModuleOptions{},
		impl: &RustModDefaultImpl{},
	}
}

// RustModule abstracts the Rust module (Cargo) data of a project.
type RustModule struct {
	impl     RustModImplementation
	opts     *RustModuleOptions
	Packages []*RustPackage
}

// RustModuleOptions are the options for the Rust module scanner.
type RustModuleOptions struct {
	Path         string // Path to the dir where Cargo.toml resides
	ScanLicenses bool   // Scan licenses from every possible place unless false
}

// Options returns a pointer to the module options set.
func (mod *RustModule) Options() *RustModuleOptions {
	return mod.opts
}

// SetScanLicenses sets the ScanLicenses option on the module.
func (mod *RustModule) SetScanLicenses(v bool) {
	mod.opts.ScanLicenses = v
}

// GetPackageConverters returns the module's packages as spdxPackageConverter interfaces.
func (mod *RustModule) GetPackageConverters() []spdxPackageConverter {
	converters := make([]spdxPackageConverter, len(mod.Packages))
	for i, pkg := range mod.Packages {
		converters[i] = pkg
	}
	return converters
}

// RustPackage holds basic package data we need for a Rust crate.
type RustPackage struct {
	TmpDir        bool
	Name          string
	Version       string
	LocalDir      string
	LicenseID     string
	CopyrightText string
}

// GetName returns the package name.
func (pkg *RustPackage) GetName() string { return pkg.Name }

// ToSPDXPackage builds a spdx package from the Rust package data.
func (pkg *RustPackage) ToSPDXPackage() (*Package, error) {
	downloadURL := fmt.Sprintf(
		"https://crates.io/api/v1/crates/%s/%s/download",
		pkg.Name, pkg.Version,
	)

	spdxPackage := NewPackage()
	spdxPackage.Options().Prefix = "cargo"
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

// PackageURL returns a purl if the Rust package has enough data to generate
// one. If data is missing, it will return an empty string.
func (pkg *RustPackage) PackageURL() string {
	if pkg.Name == "" || pkg.Version == "" {
		return ""
	}

	return purl.NewPackageURL(
		purl.TypeCargo, "", pkg.Name,
		pkg.Version, nil, "",
	).ToString()
}

// RustModImplementation is the interface that the Rust module scanner uses.
type RustModImplementation interface {
	BuildPackageList(path string) ([]*RustPackage, error)
	DownloadPackage(*RustPackage, *RustModuleOptions, bool) error
	RemoveDownloads([]*RustPackage) error
	LicenseReader() (*license.Reader, error)
	ScanPackageLicense(*RustPackage, *license.Reader, *RustModuleOptions) error
}

// Open initializes the Rust module from the configured path.
func (mod *RustModule) Open() error {
	pkgs, err := mod.impl.BuildPackageList(mod.opts.Path)
	if err != nil {
		return fmt.Errorf("building Rust package list: %w", err)
	}
	mod.Packages = pkgs
	return nil
}

// RemoveDownloads cleans all downloads.
func (mod *RustModule) RemoveDownloads() error {
	return mod.impl.RemoveDownloads(mod.Packages)
}

// ScanLicenses scans the licenses and populates the fields.
func (mod *RustModule) ScanLicenses() error {
	if mod.Packages == nil {
		return errors.New("unable to scan license files, package list is nil")
	}

	reader, err := mod.impl.LicenseReader()
	if err != nil {
		return fmt.Errorf("creating license scanner: %w", err)
	}

	return scanPackageLicenses(
		mod.Packages, "Rust", reader,
		func(pkg *RustPackage) error {
			return mod.impl.DownloadPackage(pkg, mod.opts, false)
		},
		func(pkg *RustPackage, r *license.Reader) error {
			return mod.impl.ScanPackageLicense(pkg, r, mod.opts)
		},
	)
}

// RustModDefaultImpl is the default implementation of RustModImplementation.
type RustModDefaultImpl struct {
	licenseReader *license.Reader
}

// cargoMetadataOutput represents the JSON output of `cargo metadata`.
type cargoMetadataOutput struct {
	Packages []cargoMetadataPackage `json:"packages"`
}

// cargoMetadataPackage represents a single package in cargo metadata output.
type cargoMetadataPackage struct {
	Name    string  `json:"name"`
	Version string  `json:"version"`
	Source  *string `json:"source"`
}

// BuildPackageList runs cargo metadata and builds a list of Rust packages.
func (di *RustModDefaultImpl) BuildPackageList(path string) ([]*RustPackage, error) {
	cargoBin, err := exec.LookPath("cargo")
	if err != nil {
		return nil, errors.New("unable to build Rust package list, cargo executable not found")
	}

	cargoRun := command.NewWithWorkDir(
		path, cargoBin, "metadata", "--format-version", "1",
	)
	output, err := cargoRun.RunSilentSuccessOutput()
	if err != nil {
		return nil, fmt.Errorf("while calling cargo metadata to get dependencies: %w", err)
	}

	metadata := &cargoMetadataOutput{}
	if err := json.Unmarshal([]byte(output.Output()), metadata); err != nil {
		return nil, fmt.Errorf("parsing cargo metadata output: %w", err)
	}

	pkgs := make([]*RustPackage, 0, len(metadata.Packages))
	for _, p := range metadata.Packages {
		// Skip workspace root packages (source is null for local packages)
		if p.Source == nil {
			continue
		}

		// Only include packages from crates.io
		if !strings.Contains(*p.Source, cratesIORegistry) {
			logrus.Debugf("Skipping non-crates.io package %s (source: %s)", p.Name, *p.Source)
			continue
		}

		pkgs = append(pkgs, &RustPackage{
			Name:    p.Name,
			Version: p.Version,
		})
	}

	logrus.Infof("Found %d Rust packages from cargo metadata", len(pkgs))
	return pkgs, nil
}

// DownloadPackage takes a RustPackage, downloads it from crates.io, and sets
// the download dir in the LocalDir field.
func (di *RustModDefaultImpl) DownloadPackage(pkg *RustPackage, _ *RustModuleOptions, force bool) error {
	if pkg.LocalDir != "" && helpers.Exists(pkg.LocalDir) && !force {
		logrus.WithField("package", pkg.Name).Infof("Not downloading %s as it already has local data", pkg.Name)
		return nil
	}

	logrus.WithField("package", pkg.Name).Debugf("Downloading package %s@%s", pkg.Name, pkg.Version)

	// Create temp directory
	if !helpers.Exists(filepath.Join(os.TempDir(), rustDownloadDir)) {
		if err := os.MkdirAll(
			filepath.Join(os.TempDir(), rustDownloadDir), os.FileMode(0o755),
		); err != nil {
			return fmt.Errorf("creating parent tmpdir: %w", err)
		}
	}

	tmpDir, err := os.MkdirTemp(filepath.Join(os.TempDir(), rustDownloadDir), "package-download-")
	if err != nil {
		return fmt.Errorf("creating temporary dir: %w", err)
	}

	downloadURL := fmt.Sprintf(
		"https://crates.io/api/v1/crates/%s/%s/download",
		pkg.Name, pkg.Version,
	)

	// Download from crates.io using release-utils http agent
	agent := http.NewAgent()
	data, err := agent.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("downloading %s from crates.io (%s): %w", pkg.Name, downloadURL, err)
	}

	// Extract gzipped tarball to temp directory
	if err := extractTarGz(data, tmpDir); err != nil {
		return fmt.Errorf("extracting crate tarball: %w", err)
	}

	logrus.WithField("package", pkg.Name).Infof("Rust Package %s (version %s) downloaded to %s", pkg.Name, pkg.Version, tmpDir)
	pkg.LocalDir = tmpDir
	pkg.TmpDir = true
	return nil
}

// extractTarGz extracts a gzipped tar archive to the destination directory.
// Source tarballs typically have format: package-version/path, so we strip
// the first component.
func extractTarGz(data []byte, destDir string) error {
	gzReader, err := gzip.NewReader(strings.NewReader(string(data)))
	if err != nil {
		return fmt.Errorf("opening gzip reader: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar entry: %w", err)
		}

		// Strip the first path component (package-version/)
		parts := strings.SplitN(header.Name, "/", 2)
		if len(parts) < 2 {
			continue
		}
		destPath := filepath.Join(destDir, parts[1])

		// Validate path to prevent path traversal
		if !strings.HasPrefix(filepath.Clean(destPath), filepath.Clean(destDir)) {
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(destPath, 0o755); err != nil {
				return fmt.Errorf("creating directory: %w", err)
			}
		case tar.TypeReg:
			// Create parent directories
			if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
				return fmt.Errorf("creating parent directory: %w", err)
			}

			outFile, err := os.Create(destPath)
			if err != nil {
				return fmt.Errorf("creating file: %w", err)
			}

			limited := io.LimitReader(tarReader, maxRustExtractFileSize)
			_, err = io.Copy(outFile, limited)
			outFile.Close()
			if err != nil {
				return fmt.Errorf("extracting file: %w", err)
			}
		}
	}
	return nil
}

// RemoveDownloads takes a list of packages and removes their downloads.
func (di *RustModDefaultImpl) RemoveDownloads(packageList []*RustPackage) error {
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
func (di *RustModDefaultImpl) LicenseReader() (*license.Reader, error) {
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
func (di *RustModDefaultImpl) ScanPackageLicense(
	pkg *RustPackage, reader *license.Reader, _ *RustModuleOptions,
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

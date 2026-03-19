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
	nodeDownloadDir = spdxTempDir + "/node-scanner"
	NodePackageFile = "package.json"
)

// NodePackage basic pkg data we need.
type NodePackage struct {
	TmpDir        bool
	Name          string // e.g. "express", "@types/node"
	Version       string // e.g. "4.18.2"
	LocalDir      string
	LicenseID     string
	CopyrightText string
}

// GetName returns the package name.
func (pkg *NodePackage) GetName() string { return pkg.Name }

// ToSPDXPackage builds an SPDX package from the node package data.
func (pkg *NodePackage) ToSPDXPackage() (*Package, error) {
	spdxPackage := NewPackage()
	spdxPackage.Options().Prefix = "npm"
	spdxPackage.Name = pkg.Name
	spdxPackage.BuildID(pkg.Name, pkg.Version)
	spdxPackage.Version = pkg.Version
	spdxPackage.LicenseConcluded = pkg.LicenseID
	spdxPackage.CopyrightText = pkg.CopyrightText

	// Build the download location URL.
	// For scoped packages like @scope/name, the tarball URL is:
	//   https://registry.npmjs.org/@scope/name/-/name-version.tgz
	// For unscoped packages:
	//   https://registry.npmjs.org/name/-/name-version.tgz
	basename := pkg.Name
	if strings.HasPrefix(pkg.Name, "@") {
		// Scoped package: extract just the name part after the slash
		parts := strings.SplitN(pkg.Name, "/", 2)
		if len(parts) == 2 {
			basename = parts[1]
		}
	}
	spdxPackage.DownloadLocation = fmt.Sprintf(
		"https://registry.npmjs.org/%s/-/%s-%s.tgz",
		pkg.Name, basename, pkg.Version,
	)

	if packageurl := pkg.PackageURL(); packageurl != "" {
		spdxPackage.ExternalRefs = append(spdxPackage.ExternalRefs, ExternalRef{
			Category: CatPackageManager,
			Type:     "purl",
			Locator:  packageurl,
		})
	}
	return spdxPackage, nil
}

// PackageURL returns a purl if the node package has enough data to generate
// one. If data is missing, it will return an empty string.
func (pkg *NodePackage) PackageURL() string {
	if pkg.Name == "" || pkg.Version == "" {
		return ""
	}

	var namespace, name string
	if strings.HasPrefix(pkg.Name, "@") {
		// Scoped package: @scope/name -> namespace="@scope", name="name"
		parts := strings.SplitN(pkg.Name, "/", 2)
		if len(parts) == 2 {
			namespace = parts[0]
			name = parts[1]
		} else {
			return ""
		}
	} else {
		namespace = ""
		name = pkg.Name
	}

	return purl.NewPackageURL(
		purl.TypeNPM, namespace, name,
		pkg.Version, nil, "",
	).ToString()
}

type NodeModuleOptions struct {
	Path         string
	ScanLicenses bool
}

// NodeModule abstracts the node module data of a project.
type NodeModule struct {
	impl     NodeModImplementation
	opts     *NodeModuleOptions
	Packages []*NodePackage
}

// Options returns a pointer to the module options set.
func (mod *NodeModule) Options() *NodeModuleOptions {
	return mod.opts
}

// SetScanLicenses sets the ScanLicenses option on the module.
func (mod *NodeModule) SetScanLicenses(v bool) {
	mod.opts.ScanLicenses = v
}

// GetPackageConverters returns the module's packages as spdxPackageConverter interfaces.
func (mod *NodeModule) GetPackageConverters() []spdxPackageConverter {
	converters := make([]spdxPackageConverter, len(mod.Packages))
	for i, pkg := range mod.Packages {
		converters[i] = pkg
	}
	return converters
}

type NodeModImplementation interface {
	BuildPackageList(path string) ([]*NodePackage, error)
	DownloadPackage(*NodePackage, *NodeModuleOptions, bool) error
	RemoveDownloads([]*NodePackage) error
	LicenseReader() (*license.Reader, error)
	ScanPackageLicense(*NodePackage, *license.Reader, *NodeModuleOptions) error
}

// NewNodeModule returns a new node module with default options.
func NewNodeModule() *NodeModule {
	return &NodeModule{
		opts: &NodeModuleOptions{},
		impl: &NodeModDefaultImpl{},
	}
}

// NewNodeModuleFromPath returns a new node module from the specified path.
func NewNodeModuleFromPath(path string) (*NodeModule, error) {
	mod := NewNodeModule()
	mod.opts.Path = path
	return mod, nil
}

// Open initializes a node module from the specified path.
func (mod *NodeModule) Open() error {
	pkgs, err := mod.impl.BuildPackageList(mod.opts.Path)
	if err != nil {
		return fmt.Errorf("building node package list: %w", err)
	}
	mod.Packages = pkgs
	return nil
}

// RemoveDownloads cleans all downloads.
func (mod *NodeModule) RemoveDownloads() error {
	return mod.impl.RemoveDownloads(mod.Packages)
}

// ScanLicenses scans the licenses and populates the fields.
func (mod *NodeModule) ScanLicenses() error {
	if mod.Packages == nil {
		return errors.New("unable to scan license files, package list is nil")
	}

	reader, err := mod.impl.LicenseReader()
	if err != nil {
		return fmt.Errorf("creating license scanner: %w", err)
	}

	return scanPackageLicenses(
		mod.Packages, "node", reader,
		func(pkg *NodePackage) error {
			return mod.impl.DownloadPackage(pkg, mod.opts, false)
		},
		func(pkg *NodePackage, r *license.Reader) error {
			return mod.impl.ScanPackageLicense(pkg, r, mod.opts)
		},
	)
}

type NodeModDefaultImpl struct {
	licenseReader *license.Reader
}

// BuildPackageList builds a list of node packages by running npm ls --all --json.
// If npm is not available, it falls back to reading package.json directly.
func (di *NodeModDefaultImpl) BuildPackageList(path string) ([]*NodePackage, error) {
	npmBin, err := exec.LookPath("npm")
	if err != nil {
		logrus.Warn("npm not found, falling back to reading package.json directly")
		return di.buildPackageListFromFile(path)
	}

	npmRun := command.NewWithWorkDir(path, npmBin, "ls", "--all", "--json")
	output, err := npmRun.RunSilentSuccessOutput()
	if err != nil {
		logrus.Warnf("npm ls failed, falling back to package.json: %v", err)
		return di.buildPackageListFromFile(path)
	}

	// Parse the JSON output from npm ls
	type npmDep struct {
		Version      string             `json:"version"`
		Dependencies map[string]*npmDep `json:"dependencies"`
	}
	type npmOutput struct {
		Dependencies map[string]*npmDep `json:"dependencies"`
	}

	var result npmOutput
	if err := json.Unmarshal([]byte(output.Output()), &result); err != nil {
		return nil, fmt.Errorf("parsing npm ls output: %w", err)
	}

	// Flatten the dependency tree recursively to get unique name@version pairs
	seen := map[string]bool{}
	var pkgs []*NodePackage

	var flatten func(deps map[string]*npmDep)
	flatten = func(deps map[string]*npmDep) {
		for name, dep := range deps {
			key := name + "@" + dep.Version
			if seen[key] {
				continue
			}
			seen[key] = true

			pkgs = append(pkgs, &NodePackage{
				Name:    name,
				Version: dep.Version,
			})

			if dep.Dependencies != nil {
				flatten(dep.Dependencies)
			}
		}
	}

	if result.Dependencies != nil {
		flatten(result.Dependencies)
	}

	logrus.Infof("Found %d node packages from dependency tree", len(pkgs))
	return pkgs, nil
}

// buildPackageListFromFile reads package.json and extracts dependencies
// and devDependencies keys (without version resolution).
func (di *NodeModDefaultImpl) buildPackageListFromFile(path string) ([]*NodePackage, error) {
	pkgFile := filepath.Join(path, NodePackageFile)
	if !helpers.Exists(pkgFile) {
		return nil, fmt.Errorf("package.json not found in %s", path)
	}

	data, err := os.ReadFile(pkgFile)
	if err != nil {
		return nil, fmt.Errorf("reading package.json: %w", err)
	}

	type packageJSON struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}

	var pj packageJSON
	if err := json.Unmarshal(data, &pj); err != nil {
		return nil, fmt.Errorf("parsing package.json: %w", err)
	}

	var pkgs []*NodePackage
	seen := map[string]bool{}

	addDeps := func(deps map[string]string) {
		for name, version := range deps {
			// Strip version prefixes like ^, ~, >= etc. for a best-effort version
			version = strings.TrimLeft(version, "^~>=<! ")
			key := name + "@" + version
			if seen[key] {
				continue
			}
			seen[key] = true
			pkgs = append(pkgs, &NodePackage{
				Name:    name,
				Version: version,
			})
		}
	}

	addDeps(pj.Dependencies)
	addDeps(pj.DevDependencies)

	logrus.Infof(
		"Parsed package.json, found %d dependencies (without full resolution)",
		len(pkgs),
	)
	return pkgs, nil
}

// DownloadPackage takes a pkg, downloads it from the npm registry and sets
// the download dir in the LocalDir field.
func (di *NodeModDefaultImpl) DownloadPackage(pkg *NodePackage, _ *NodeModuleOptions, force bool) error {
	if pkg.LocalDir != "" && helpers.Exists(pkg.LocalDir) && !force {
		logrus.WithField("package", pkg.Name).Infof("Not downloading %s as it already has local data", pkg.Name)
		return nil
	}

	logrus.WithField("package", pkg.Name).Debugf("Downloading package %s@%s", pkg.Name, pkg.Version)

	// Create temp directory
	if !helpers.Exists(filepath.Join(os.TempDir(), nodeDownloadDir)) {
		if err := os.MkdirAll(
			filepath.Join(os.TempDir(), nodeDownloadDir), os.FileMode(0o755),
		); err != nil {
			return fmt.Errorf("creating parent tmpdir: %w", err)
		}
	}

	tmpDir, err := os.MkdirTemp(filepath.Join(os.TempDir(), nodeDownloadDir), "package-download-")
	if err != nil {
		return fmt.Errorf("creating temporary dir: %w", err)
	}

	// Fetch package metadata from the npm registry to get the tarball URL
	registryURL := fmt.Sprintf("https://registry.npmjs.org/%s/%s", pkg.Name, pkg.Version)
	agent := http.NewAgent()
	data, err := agent.Get(registryURL)
	if err != nil {
		return fmt.Errorf("fetching npm registry metadata for %s@%s (%s): %w", pkg.Name, pkg.Version, registryURL, err)
	}

	// Parse the registry response to get the tarball URL
	type registryResponse struct {
		Dist struct {
			Tarball string `json:"tarball"`
		} `json:"dist"`
	}

	var regResp registryResponse
	if err := json.Unmarshal(data, &regResp); err != nil {
		return fmt.Errorf("parsing registry response for %s: %w", pkg.Name, err)
	}

	if regResp.Dist.Tarball == "" {
		return fmt.Errorf("no tarball URL found for %s@%s", pkg.Name, pkg.Version)
	}

	// Download the tarball
	tarballData, err := agent.Get(regResp.Dist.Tarball)
	if err != nil {
		return fmt.Errorf("downloading tarball for %s (%s): %w", pkg.Name, regResp.Dist.Tarball, err)
	}

	// Extract the tgz to the temp directory
	if err := extractTgz(tarballData, tmpDir); err != nil {
		return fmt.Errorf("extracting npm tarball: %w", err)
	}

	logrus.WithField("package", pkg.Name).Infof("Node package %s@%s downloaded to %s", pkg.Name, pkg.Version, tmpDir)
	pkg.LocalDir = tmpDir
	pkg.TmpDir = true
	return nil
}

// extractTgz extracts a .tgz archive to the destination directory.
// npm tarballs have a "package/" prefix in the tar entries, which is stripped.
func extractTgz(data []byte, destDir string) error {
	gr, err := gzip.NewReader(strings.NewReader(string(data)))
	if err != nil {
		return fmt.Errorf("opening gzip reader: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar entry: %w", err)
		}

		// npm tarballs have a "package/" prefix in entries, strip it
		name := header.Name
		parts := strings.SplitN(name, "/", 2)
		if len(parts) < 2 {
			continue
		}
		destPath := filepath.Join(destDir, parts[1])

		// Sanitize path to prevent zip-slip
		if !strings.HasPrefix(filepath.Clean(destPath), filepath.Clean(destDir)+string(os.PathSeparator)) {
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

			limited := io.LimitReader(tr, maxExtractFileSize)
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
func (di *NodeModDefaultImpl) RemoveDownloads(packageList []*NodePackage) error {
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
func (di *NodeModDefaultImpl) LicenseReader() (*license.Reader, error) {
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
func (di *NodeModDefaultImpl) ScanPackageLicense(
	pkg *NodePackage, reader *license.Reader, _ *NodeModuleOptions,
) error {
	dir := pkg.LocalDir
	if dir == "" {
		return fmt.Errorf("no local directory set for package %s", pkg.Name)
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

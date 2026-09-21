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
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/blang/semver/v4"

	"sigs.k8s.io/release-utils/helpers"

	"sigs.k8s.io/bom/pkg/license"
)

type YamlBuildArtifact struct {
	Type      string `json:"type"      yaml:"type"` //  directory
	Source    string `json:"source"    yaml:"source"`
	License   string `json:"license"   yaml:"license"`   // SPDX license ID Apache-2.0
	GoModules *bool  `json:"gomodules" yaml:"gomodules"` // Shoud we scan go modules
}

type YamlBOMConfiguration struct {
	Namespace string `json:"namespace" yaml:"namespace"`
	License   string `json:"license"   yaml:"license"` // Document wide license
	Name      string `json:"name"      yaml:"name"`
	Creator   struct {
		Person string `json:"person" yaml:"person"`
		Tool   string `json:"tool"   yaml:"tool"`
	} `json:"creator" yaml:"creator"`
	ExternalDocRefs []ExternalDocumentRef `json:"external-docs" yaml:"external-docs"`
	// LegacyExternalDocRefs reads the Go field name bom v0.7 accepted
	// by accident instead of the documented external-docs key.
	LegacyExternalDocRefs []ExternalDocumentRef `json:"externalDocRefs" yaml:"-"`
	Artifacts             []*YamlBuildArtifact  `json:"artifacts"       yaml:"artifacts"`
}

// NewDocBuilderOption is a function with operates on a newDocBuilderSettings object.
type NewDocBuilderOption func(*newDocBuilderSettings)

type newDocBuilderSettings struct {
	format Format
}

// WithFormat returns an NewDocBuilderOption setting the format.
func WithFormat(format Format) NewDocBuilderOption {
	return func(settings *newDocBuilderSettings) {
		settings.format = format
	}
}

func NewDocBuilder(options ...NewDocBuilderOption) *DocBuilder {
	settings := &newDocBuilderSettings{
		format: FormatTagValue,
	}
	for _, option := range options {
		option(settings)
	}
	db := &DocBuilder{
		options: &defaultDocBuilderOpts,
		impl: &defaultDocBuilderImpl{
			format: settings.format,
		},
	}
	return db
}

// DocBuilder is a tool to write SPDX SBOMs. It is configurable by
// defining values in its DocBuilderOptions. Options to customize the
// generated document are passed to the Generate() method in DocGenerateOptions
// struct.
type DocBuilder struct {
	options *DocBuilderOptions
	impl    DocBuilderImplementation
}

// Generate creates a new SPDX SBOM. The resulting document will describe the all
// artifacts specified in the DocGenerateOptions struct passed.
func (db *DocBuilder) Generate(genopts *DocGenerateOptions) (*Document, error) {
	if err := db.impl.ReadYamlConfiguration(genopts.ConfigFile, genopts); err != nil {
		return nil, fmt.Errorf("parsing configuration file: %w", err)
	}

	if err := db.impl.ValidateOptions(genopts); err != nil {
		return nil, fmt.Errorf("checking build options: %w", err)
	}

	doc, err := db.impl.GenerateDocument(genopts)
	if err != nil {
		return nil, err
	}
	return doc, nil
}

type DocGenerateOptions struct {
	AnalyseLayers       bool                  // A flag that controls if deep layer analysis should be performed
	NoGitignore         bool                  // Do not read exclusions from gitignore file
	Offline             bool                  // Do not reach the network while scanning
	ProcessGoModules    bool                  // Extract the dependencies of the codebases found in directories and archives
	OnlyDirectDeps      bool                  // Only include direct dependencies from go.mod
	ScanLicenses        bool                  // Deprecated: files are always classified, this has no effect
	ScanImages          bool                  // Deprecated: images are always scanned, this has no effect
	ConfigFile          string                // Path to SBOM configuration file
	Format              string                // Output format
	OutputFile          string                // Output location
	Name                string                // Name to use in the resulting document
	Namespace           string                // Namespace for the document (a unique URI)
	CreatorPerson       string                // Document creator information
	License             string                // Deprecated: a document license was never applied, this has no effect
	LicenseListVersion  string                // Version of the SPDX license list recorded in the document (eg v3.28.0)
	Tarballs            []string              // A slice of docker archives (tar)
	Archives            []string              // A list of archive files to add as packages
	Files               []string              // A slice of naked files to include in the bom
	Images              []string              // A slice of docker images
	Directories         []string              // A slice of directories to convert into packages
	IgnorePatterns      []string              // A slice of gitignore-style patterns to ignore when scanning dirs
	ExternalDocumentRef []ExternalDocumentRef // List of external documents related to the bom
}

func (o *DocGenerateOptions) Validate() error {
	if len(o.Tarballs) == 0 &&
		len(o.Files) == 0 &&
		len(o.Images) == 0 &&
		len(o.Directories) == 0 &&
		len(o.Archives) == 0 {
		return errors.New(
			"to build a document at least an image, tarball, directory or a file has to be specified",
		)
	}

	if o.ConfigFile != "" && !helpers.Exists(o.ConfigFile) {
		return errors.New("the specified configuration file was not found")
	}

	// Check namespace is a valid URL
	if _, err := url.Parse(o.Namespace); err != nil {
		return fmt.Errorf("parsing the namespace URL: %w", err)
	}

	// Licenses are matched against the SPDX license list embedded in
	// bom, and the version only labels the document: it has to name a
	// release.
	if strings.EqualFold(o.LicenseListVersion, "latest") {
		return errors.New(
			"the license list version must name a release (eg " + license.DefaultCatalogOpts.Version +
				"), fetching the latest SPDX license list is no longer supported",
		)
	}
	if _, err := licenseListVersion(o.LicenseListVersion); err != nil {
		return err
	}
	return nil
}

// licenseListVersion returns the SPDX license list version a document
// records (major.minor) for the version given, as in v3.28.0 or 3.21,
// defaulting to the version of the embedded catalog.
func licenseListVersion(ver string) (string, error) {
	if ver == "" {
		ver = license.DefaultCatalogOpts.Version
	}
	v, err := semver.ParseTolerant(ver)
	if err != nil {
		return "", fmt.Errorf("parsing license list version %q: %w", ver, err)
	}
	return fmt.Sprintf("%d.%d", v.Major, v.Minor), nil
}

type DocBuilderOptions struct {
	WorkDir string // Working directory (defaults to a tmp dir)
}

var defaultDocBuilderOpts = DocBuilderOptions{
	WorkDir: filepath.Join(os.TempDir(), "spdx-docbuilder"),
}

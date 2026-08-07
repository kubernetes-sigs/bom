/*
Copyright 2023 The Kubernetes Authors.

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
	"fmt"
	"os"
	"strings"

	"github.com/blang/semver/v4"
	"github.com/sirupsen/logrus"

	"sigs.k8s.io/yaml"

	"sigs.k8s.io/bom/internal/generate"
	"sigs.k8s.io/bom/pkg/license"
)

type DocBuilderImplementation interface {
	WriteDoc(*Document, string) error
	ReadYamlConfiguration(string, *DocGenerateOptions) error
	ValidateOptions(*DocGenerateOptions) error
	GenerateDocument(*DocGenerateOptions) (*Document, error)
}

// defaultDocBuilderImpl is the default implementation for the
// SPDX document builder.
type defaultDocBuilderImpl struct {
	format Format
}

// GenerateDocument runs the protobom-native generation engine over the
// requested artifacts and converts the result to the legacy model.
func (builder *defaultDocBuilderImpl) GenerateDocument(genopts *DocGenerateOptions) (*Document, error) {
	if genopts.AnalyseLayers {
		logrus.Warn("Deep image layer analysis is no longer supported, ignoring AnalyseLayers")
	}

	pdoc, err := generate.Document(context.Background(), &generate.Options{
		Name:           genopts.Name,
		Namespace:      genopts.Namespace,
		CreatorPerson:  genopts.CreatorPerson,
		Directories:    genopts.Directories,
		Images:         genopts.Images,
		ImageArchives:  genopts.Tarballs,
		Archives:       genopts.Archives,
		Files:          genopts.Files,
		IgnorePatterns: genopts.IgnorePatterns,
	})
	if err != nil {
		return nil, fmt.Errorf("generating document: %w", err)
	}

	doc, err := FromProtobom(pdoc)
	if err != nil {
		return nil, fmt.Errorf("converting to the legacy model: %w", err)
	}

	// Fill in the document fields the protobom metadata does not
	// carry. The license list version comes from the embedded catalog
	// unless one was specified, trimmed to major.minor.
	ver := strings.TrimPrefix(license.DefaultCatalogOpts.Version, "v")
	if genopts.LicenseListVersion != "" {
		ver = strings.TrimPrefix(genopts.LicenseListVersion, "v")
	}
	v, err := semver.New(ver)
	if err != nil {
		return nil, fmt.Errorf("parsing license list semver string %q: %w", ver, err)
	}
	doc.LicenseListVersion = fmt.Sprintf("%d.%d", v.Major, v.Minor)
	doc.ExternalDocRefs = genopts.ExternalDocumentRef
	// The organization credit is fixed in the legacy model; the engine
	// records only the creator person and the tool.
	doc.Creator.Organization = "Kubernetes Release Engineering"
	return doc, nil
}

// ReadYamlConfiguration reads a yaml configuration and
// set the values in an options struct.
func (builder *defaultDocBuilderImpl) ReadYamlConfiguration(
	path string, genopts *DocGenerateOptions,
) (err error) {
	// NOOP if no YAML file is specified
	if path == "" {
		return nil
	}

	yamldata, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading yaml SBOM configuration: %w", err)
	}

	conf := &YamlBOMConfiguration{}
	if err := yaml.Unmarshal(yamldata, conf); err != nil {
		return fmt.Errorf("unmarshalling SBOM configuration YAML: %w", err)
	}

	if conf.Name != "" {
		genopts.Name = conf.Name
	}

	if conf.Namespace != "" {
		genopts.Namespace = conf.Namespace
	}

	if conf.Creator.Person != "" {
		genopts.CreatorPerson = conf.Creator.Person
	}

	if conf.License != "" {
		genopts.License = conf.License
	}

	genopts.ExternalDocumentRef = conf.ExternalDocRefs

	// Add all the artifacts
	for _, artifact := range conf.Artifacts {
		logrus.Infof("Configuration has artifact of type %s: %s", artifact.Type, artifact.Source)
		switch artifact.Type {
		case "directory":
			genopts.Directories = append(genopts.Directories, artifact.Source)
		case "image":
			genopts.Images = append(genopts.Images, artifact.Source)
		case "docker-archive":
			genopts.Tarballs = append(genopts.Tarballs, artifact.Source)
		case "file":
			genopts.Files = append(genopts.Files, artifact.Source)
		case "archive":
			genopts.Archives = append(genopts.Archives, artifact.Source)
		}
	}

	return nil
}

func (builder *defaultDocBuilderImpl) ValidateOptions(genopts *DocGenerateOptions) error {
	if err := genopts.Validate(); err != nil {
		return fmt.Errorf("checking build options: %w", err)
	}
	return nil
}

// WriteDoc renders the document to a file.
func (builder *defaultDocBuilderImpl) WriteDoc(doc *Document, path string) error {
	markup, err := doc.Render()
	if err != nil {
		return fmt.Errorf("generating document markup: %w", err)
	}
	logrus.Infof("writing document to %s", path)

	if err := os.WriteFile(path, []byte(markup), os.FileMode(0o644)); err != nil {
		return fmt.Errorf(
			"writing document markup to file: %w",
			err,
		)
	}
	return nil
}

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

	"github.com/sirupsen/logrus"

	"sigs.k8s.io/yaml"

	"sigs.k8s.io/bom/internal/generate"
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
	// Tell callers when they ask for something the engine does not
	// offer anymore, rather than silently ignoring it.
	if genopts.AnalyseLayers {
		logrus.Warn("Deep image layer analysis is no longer supported, ignoring AnalyseLayers")
	}
	if !genopts.ScanImages && len(genopts.Images)+len(genopts.Tarballs) > 0 {
		logrus.Warn("Images are always scanned for their packages, ignoring ScanImages")
	}
	if genopts.License != "" {
		logrus.Warnf("A document license cannot be declared, ignoring license %q", genopts.License)
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
		NoGitignore:    genopts.NoGitignore,
		OnlyDirectDeps: genopts.OnlyDirectDeps,
		NoDependencies: !genopts.ProcessGoModules,
		Offline:        genopts.Offline,
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
	doc.LicenseListVersion, err = licenseListVersion(genopts.LicenseListVersion)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, ref := range genopts.ExternalDocumentRef {
		if err := ref.Validate(); err != nil {
			logrus.Warnf("Skipping external document reference: %v", err)
			continue
		}
		if seen[ref.DocumentRefID()] {
			logrus.Warnf("Skipping duplicate external document reference %s", ref.DocumentRefID())
			continue
		}
		seen[ref.DocumentRefID()] = true
		doc.ExternalDocRefs = append(doc.ExternalDocRefs, ref)
	}
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
	if len(conf.LegacyExternalDocRefs) > 0 {
		logrus.Warn("The externalDocRefs configuration key is deprecated, use external-docs")
		genopts.ExternalDocumentRef = append(genopts.ExternalDocumentRef, conf.LegacyExternalDocRefs...)
	}

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
	return genopts.Validate()
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

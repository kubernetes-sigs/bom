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

package license

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/carabiner-dev/unpack/filesystem/processors"
	unpacklicense "github.com/carabiner-dev/unpack/license"
	licenseclassifier "github.com/google/licenseclassifier/v2"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/sirupsen/logrus"
)

// ReaderDefaultImpl is the default license reader implementation. It
// classifies files with the license scanner from
// github.com/carabiner-dev/unpack, which carries its own embedded corpus
// of license texts, so no license list needs to be downloaded or written
// to disk to recognize a license.
//
// Licenses returned by this implementation carry their SPDX identifier
// but none of the metadata published in the SPDX license list: the
// classifier reports which license a file holds, not what that license
// says. Use a Catalog to look up the full record for an identifier.
type ReaderDefaultImpl struct{}

// classify runs a single file through the license scanner and returns
// the SPDX identifier of the license it holds, empty when the file
// matches none.
func classify(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolving %q: %w", path, err)
	}
	// The scanner reads FileName from the filesystem it is handed.
	node := &sbom.Node{FileName: filepath.Base(abs)}
	if err := processors.NewLicenseScanner().Process(
		nil, os.DirFS(filepath.Dir(abs)), node,
	); err != nil {
		return "", fmt.Errorf("classifying %q: %w", path, err)
	}
	if licenses := node.GetLicenses(); len(licenses) > 0 {
		return licenses[0], nil
	}
	return "", nil
}

// ClassifyFile takes a file path and returns the most probable license tag.
//
// The scanner reports the single best match, so no additional tags are
// ever returned.
func (d *ReaderDefaultImpl) ClassifyFile(path string) (licenseTag string, moreTags []string, err error) {
	licenseTag, err = classify(path)
	if err != nil {
		return "", nil, err
	}
	if licenseTag == "" {
		logrus.Debugf("File does not match a known license: %s", path)
	}
	return licenseTag, []string{}, nil
}

// ClassifyLicenseFiles takes a list of paths and tries to find return all licenses found in it.
func (d *ReaderDefaultImpl) ClassifyLicenseFiles(paths []string) (
	licenseList []*ClassifyResult, unrecognizedPaths []string, err error,
) {
	licenseList = []*ClassifyResult{}
	// Run the files through the clasifier
	for _, f := range paths {
		label, _, err := d.ClassifyFile(f)
		if err != nil {
			return nil, unrecognizedPaths, fmt.Errorf("classifying file: %w", err)
		}
		if label == "" {
			unrecognizedPaths = append(unrecognizedPaths, f)
			continue
		}
		licenseText, err := os.ReadFile(f)
		if err != nil {
			return nil, nil, fmt.Errorf("reading license text: %w", err)
		}
		// Apend to the return results
		licenseList = append(licenseList, &ClassifyResult{f, string(licenseText), &License{
			LicenseID: label,
			Name:      label,
		}})
	}
	if len(paths) != len(licenseList) {
		logrus.Debugf(
			"License classifier recognized %d/%d of the license files",
			len(licenseList), len(paths),
		)
	}
	return licenseList, unrecognizedPaths, nil
}

// LicenseFromLabel returns a license from its label, normalizing aliases
// and URLs to their SPDX identifier. Labels that normalize to nothing
// recognizable are returned as given.
func (d *ReaderDefaultImpl) LicenseFromLabel(label string) (license *License) {
	if label == "" {
		return nil
	}
	id := unpacklicense.Normalize(label, "")
	return &License{LicenseID: id, Name: id}
}

// LicenseFromFile a file path and returns its license.
func (d *ReaderDefaultImpl) LicenseFromFile(path string) (license *License, err error) {
	label, _, err := d.ClassifyFile(path)
	if err != nil {
		return nil, fmt.Errorf("classifying file: %w", err)
	}

	if label == "" {
		logrus.Debugf("File does not contain a known license: %s", path)
		return nil, nil
	}

	return &License{LicenseID: label, Name: label}, nil
}

// FindLicenseFiles will scan a directory and return files that may be licenses.
func (d *ReaderDefaultImpl) FindLicenseFiles(path string) ([]string, error) {
	logrus.Debugf("Scanning %s for license files", path)
	licenseList := []string{}
	re := regexp.MustCompile(licenseFilanameRe)
	if err := filepath.Walk(path,
		func(path string, finfo os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Directories are ignored
			if finfo.IsDir() {
				return nil
			}

			// No go source files are considered
			if filepath.Ext(path) == ".go" {
				return nil
			}
			// Check if tehe file matches the license regexp
			if re.MatchString(filepath.Base(path)) {
				licenseList = append(licenseList, path)
			}
			return nil
		}); err != nil {
		return nil, fmt.Errorf("scanning the directory for license files: %w", err)
	}
	logrus.Debugf("%d license files found in directory %s", len(licenseList), path)
	return licenseList, nil
}

// Initialize checks the options. The scanner needs no setup: its license
// corpus is embedded, so nothing is downloaded or written to disk.
func (d *ReaderDefaultImpl) Initialize(opts *ReaderOptions) error {
	if err := opts.Validate(); err != nil {
		return fmt.Errorf("validating the license reader options: %w", err)
	}
	return nil
}

// Classifier returns the license classifier.
//
// Deprecated: classification is performed by the license scanner in
// github.com/carabiner-dev/unpack, which does not expose its classifier.
// This method always returns nil and will be removed in a future major
// version.
func (d *ReaderDefaultImpl) Classifier() *licenseclassifier.Classifier {
	return nil
}

// Catalog returns the reader's SPDX object.
//
// Deprecated: the reader no longer builds a catalog to classify files.
// Build one with NewCatalogWithOptions if you need the SPDX license list.
// This method always returns nil and will be removed in a future major
// version.
func (d *ReaderDefaultImpl) Catalog() *Catalog {
	return nil
}

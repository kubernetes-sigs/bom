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
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"

	"sigs.k8s.io/bom/internal/sbomio"
)

// OpenDoc reads an SBOM like bom.Open in sigs.k8s.io/bom/pkg/bom does
// and returns it converted to the legacy object model (see
// FromProtobom).
//
// Deprecated: use bom.Open in sigs.k8s.io/bom/pkg/bom, which returns the
// document in the protobom model, or convert its result with
// FromProtobom where the legacy model is still needed.
func OpenDoc(path string) (*Document, error) {
	pdoc, err := sbomio.Open(path)
	if err != nil {
		return nil, err
	}
	doc, err := fromParsedProtobom(pdoc)
	if err != nil {
		return nil, fmt.Errorf("converting document: %w", err)
	}
	return doc, nil
}

// detectSBOMEncoding reads a few bytes from the SBOM and returns.
func DetectSBOMEncoding(f *os.File) (format string, err error) {
	fileScanner := bufio.NewScanner(f)
	fileScanner.Split(bufio.ScanLines)

	looksLikeCDX := true
	for fileScanner.Scan() {
		// In JSON, the spdx version field would be quoted
		if strings.Contains(fileScanner.Text(), "\"spdxVersion\"") {
			format = "spdx+json"
			break
		} else if strings.Contains(fileScanner.Text(), "SPDXVersion:") {
			format = "spdx"
			break
		}

		if strings.Contains(fileScanner.Text(), "bomFormat") && strings.Contains(fileScanner.Text(), "CycloneDX") {
			looksLikeCDX = true
		}
	}
	if _, err := f.Seek(0, 0); err != nil {
		return "", fmt.Errorf("rewinding file pointer: %w", err)
	}

	if format != "" {
		return format, nil
	}

	// Print a more accurate warning if trying to ingest a
	// CycloneDX document to avoid confusion
	if looksLikeCDX {
		logrus.Warn("The scanned document looks like a CycloneDX SBOM (not supported by bom)")
	} else {
		logrus.Warn("Unable to detect SBOM encoding")
	}

	return "", nil
}

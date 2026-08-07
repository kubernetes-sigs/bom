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
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/protobom/protobom/pkg/reader"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/sirupsen/logrus"

	"sigs.k8s.io/release-utils/http"

	"sigs.k8s.io/bom/internal/tagvalue"
)

// OpenDoc opens a file, parses a SPDX tag-value file and returns a loaded
// spdx.Document object. This functions has the cyclomatic chec disabled as
// it spans specific cases for each of the tags it recognizes.
func OpenDoc(path string) (*Document, error) {
	pdoc, err := OpenProtobom(path)
	if err != nil {
		return nil, err
	}
	doc, err := FromProtobom(pdoc)
	if err != nil {
		return nil, fmt.Errorf("converting document: %w", err)
	}
	return doc, nil
}

// OpenProtobom reads an SBOM from the same sources as OpenDoc and
// returns it as a protobom document, the format-neutral model the
// document is parsed into before conversion. Consumers that do not
// need the legacy object model should prefer it.
func OpenProtobom(path string) (*sbom.Document, error) {
	file, cleanup, err := openSBOMFile(path)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	registerFormats()

	doc, err := reader.New().ParseStream(file)
	if err != nil {
		return nil, fmt.Errorf("parsing SBOM: %w", err)
	}
	return doc, nil
}

// openSBOMFile resolves the document location to an open file: a dash
// or an empty path reads STDIN, a URL is downloaded, anything else is
// opened from disk. The returned function closes the file and removes
// it when it was buffered to a temporary location.
func openSBOMFile(path string) (*os.File, func(), error) {
	var file *os.File
	var isTemp bool
	var err error

	switch {
	case path == "-", path == "":
		if path == "" {
			fi, err := os.Stdin.Stat()
			if err != nil {
				return nil, nil, fmt.Errorf("checking stdin for data: %w", err)
			}
			if (fi.Mode() & os.ModeCharDevice) != 0 {
				return nil, nil, errors.New("document path not specified")
			}
		}
		isTemp = true
		file, err = bufferSTDIN()
		if err != nil {
			return nil, nil, fmt.Errorf("reading STDIN: %w", err)
		}
	case isURL(path):
		file, err = tempFileFromURL(path)
		if err != nil {
			return nil, nil, fmt.Errorf("get temp file from url: %w", err)
		}
		isTemp = true
	default:
		file, err = os.Open(path)
		if err != nil {
			return nil, nil, fmt.Errorf("opening document from %s: %w", path, err)
		}
	}

	return file, func() {
		file.Close()
		if isTemp {
			os.Remove(file.Name())
		}
	}, nil
}

// registerFormats makes bom's SPDX tag-value and SPDX 2.2 drivers
// available to protobom's reader. protobom recognizes those formats
// when sniffing but ships no drivers for them, so without this the
// reader rejects every tag-value document.
var registerFormats = sync.OnceFunc(tagvalue.Register)

// TODO(puerco): Perhaps this function and isURL should be part of the http agent.
func tempFileFromURL(query string) (*os.File, error) {
	file, err := os.CreateTemp("", "sbom-")
	if err != nil {
		return nil, fmt.Errorf("creating temp file for URL response: %w", err)
	}
	if err := http.NewAgent().GetToWriter(file, query); err != nil {
		return nil, fmt.Errorf("retrieving URL data from %q: %w", query, err)
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seeking to temp file start: %w", err)
	}
	return file, nil
}

func isURL(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
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

// buyfferSTDIN buffers all of STDIN to a temp file.
func bufferSTDIN() (*os.File, error) {
	file, err := os.CreateTemp("", "temp-sbom")
	if err != nil {
		return nil, fmt.Errorf("creating temp file to buffer sbom: %w", err)
	}
	if _, err := io.Copy(file, os.Stdin); err != nil {
		return nil, fmt.Errorf("writing SBOM to temporary file: %w", err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		return nil, fmt.Errorf("rewinding temporary file: %w", err)
	}
	return file, nil
}

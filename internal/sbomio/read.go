/*
Copyright 2026 The Kubernetes Authors.

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

// Package sbomio reads SBOMs into protobom documents. It is shared by
// the public reader in pkg/bom and the legacy one in pkg/spdx, so that
// both accept the same sources and the same documents.
package sbomio

import (
	"bufio"
	"bytes"
	"crypto/sha1" //nolint:gosec // SPDX 2 documents carry SHA1 checksums
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/reader"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/sirupsen/logrus"

	"sigs.k8s.io/release-utils/http"
)

// Open reads an SBOM from path: a dash or an empty path reads STDIN, a
// URL is downloaded, anything else is read from disk.
func Open(path string) (*sbom.Document, error) {
	file, cleanup, err := openFile(path)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	return parse(file)
}

// Parse reads an SBOM from r. The format is detected from the content,
// which is buffered in memory when r cannot seek.
func Parse(r io.Reader) (*sbom.Document, error) {
	rs, ok := r.(io.ReadSeeker)
	if !ok {
		data, err := io.ReadAll(r)
		if err != nil {
			return nil, fmt.Errorf("reading SBOM: %w", err)
		}
		rs = bytes.NewReader(data)
	}
	return parse(rs)
}

// parse reads a document with protobom and, when that fails, retries
// with the specification violations bom's previous parser tolerated
// repaired (see sanitize), so that documents bom read before still
// open. The error of the strict attempt is returned when the lenient
// one fails too.
//
// Documents are read with the drivers protobom ships, SPDX 2.2 and
// tag-value included, through a reader of its own: nothing is
// registered in protobom's package-level driver registry. SPDX 2.1
// documents are read like SPDX 2.2 ones (see sniffer).
func parse(rs io.ReadSeeker) (*sbom.Document, error) {
	doc, err := newReader().ParseStream(rs)
	if err == nil {
		return doc, nil
	}
	parseErr := fmt.Errorf("parsing SBOM: %w", err)

	if _, serr := rs.Seek(0, io.SeekStart); serr != nil {
		return nil, parseErr
	}
	data, rerr := io.ReadAll(rs)
	if rerr != nil {
		return nil, parseErr
	}
	fixed, fixes := sanitize(data)
	if len(fixes) == 0 {
		return nil, parseErr
	}
	doc, err = newReader().ParseStream(bytes.NewReader(fixed))
	if err != nil {
		return nil, parseErr
	}
	for _, fix := range fixes {
		logrus.Warnf("SBOM does not conform to the SPDX specification: %s", fix)
	}

	// The source data describes the document as read, not the
	// repaired copy protobom parsed.
	if sd := doc.GetMetadata().GetSourceData(); sd != nil {
		sd.Size = int64(len(data))
		sd.Hashes = sourceHashes(data)
	}
	return doc, nil
}

func newReader() *reader.Reader {
	return reader.New(reader.WithSniffer(sniffer{}))
}

// sniffer detects SBOM formats like protobom's, which does not know
// SPDX 2.1, and reads SPDX 2.1 as SPDX 2.2. That is sound: the SPDX
// 2.2 drivers parse with tools-golang, which reads every SPDX 2.x
// version and upgrades it to the 2.3 model.
type sniffer struct {
	formats.Sniffer
}

func (s sniffer) SniffReader(rs io.ReadSeeker) (formats.Format, error) {
	format, err := s.Sniffer.SniffReader(rs)
	if err == nil {
		return format, nil
	}
	if format := sniffSPDX21(rs); format != formats.EmptyFormat {
		return format, nil
	}
	return format, err //nolint:wrapcheck // protobom's own error
}

func (s sniffer) SniffFile(path string) (formats.Format, error) {
	f, err := os.Open(path)
	if err != nil {
		return formats.EmptyFormat, fmt.Errorf("opening path: %w", err)
	}
	defer f.Close()
	return s.SniffReader(f)
}

// sniffSPDX21 returns the SPDX 2.2 format in the encoding of rs when
// it holds an SPDX 2.1 document, the empty format otherwise.
func sniffSPDX21(rs io.ReadSeeker) formats.Format {
	const version = "SPDX-2.1"
	defer rs.Seek(0, io.SeekStart) //nolint:errcheck // best effort, like protobom's sniffer
	if _, err := rs.Seek(0, io.SeekStart); err != nil {
		return formats.EmptyFormat
	}
	var header struct {
		SPDXVersion string `json:"spdxVersion"`
	}
	if err := json.NewDecoder(rs).Decode(&header); err == nil {
		if header.SPDXVersion == version {
			return formats.SPDX22JSON
		}
		return formats.EmptyFormat
	}
	if _, err := rs.Seek(0, io.SeekStart); err != nil {
		return formats.EmptyFormat
	}
	scanner := bufio.NewScanner(rs)
	for scanner.Scan() {
		tag, value, ok := strings.Cut(scanner.Text(), ":")
		if ok && strings.TrimSpace(tag) == "SPDXVersion" {
			if strings.TrimSpace(value) == version {
				return formats.SPDX22TV
			}
			return formats.EmptyFormat
		}
	}
	return formats.EmptyFormat
}

func sourceHashes(data []byte) map[int32]string {
	hashes := map[int32]string{}
	for algo, h := range map[sbom.HashAlgorithm]hash.Hash{
		sbom.HashAlgorithm_SHA1:   sha1.New(), //nolint:gosec // SPDX 2 documents carry SHA1 checksums
		sbom.HashAlgorithm_SHA256: sha256.New(),
		sbom.HashAlgorithm_SHA512: sha512.New(),
	} {
		h.Write(data)
		hashes[int32(algo)] = hex.EncodeToString(h.Sum(nil))
	}
	return hashes
}

// openFile resolves the document location to an open file. The
// returned function closes the file and removes it when it was
// buffered to a temporary location.
func openFile(path string) (*os.File, func(), error) {
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
		if isTemp {
			removeTemp(file)
		} else {
			file.Close()
		}
	}, nil
}

func tempFileFromURL(query string) (*os.File, error) {
	file, err := os.CreateTemp("", "sbom-")
	if err != nil {
		return nil, fmt.Errorf("creating temp file for URL response: %w", err)
	}
	if err := http.NewAgent().GetToWriter(file, query); err != nil {
		removeTemp(file)
		return nil, fmt.Errorf("retrieving URL data from %q: %w", query, err)
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		removeTemp(file)
		return nil, fmt.Errorf("seeking to temp file start: %w", err)
	}
	return file, nil
}

// removeTemp closes and removes a temporary file.
func removeTemp(file *os.File) {
	file.Close()
	os.Remove(file.Name())
}

func isURL(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// bufferSTDIN buffers all of STDIN to a temp file.
func bufferSTDIN() (*os.File, error) {
	return bufferToTemp(os.Stdin)
}

// bufferToTemp copies r to a temp file, rewound to its start.
func bufferToTemp(r io.Reader) (*os.File, error) {
	file, err := os.CreateTemp("", "temp-sbom")
	if err != nil {
		return nil, fmt.Errorf("creating temp file to buffer sbom: %w", err)
	}
	if _, err := io.Copy(file, r); err != nil {
		removeTemp(file)
		return nil, fmt.Errorf("writing SBOM to temporary file: %w", err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		removeTemp(file)
		return nil, fmt.Errorf("rewinding temporary file: %w", err)
	}
	return file, nil
}

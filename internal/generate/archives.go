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

package generate

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/sirupsen/logrus"
)

// addArchives resolves the archive patterns and adds each matching
// tarball to the document as a top-level package: the archive is
// extracted to a temporary directory and scanned with the same
// semantics as a directory, and its package node carries the
// archive's own file name and checksums.
func addArchives(ctx context.Context, doc *sbom.Document, opts *Options) error {
	for _, pattern := range opts.Archives {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return fmt.Errorf("globbing %q: %w", pattern, err)
		}
		if len(matches) == 0 {
			logrus.Warnf("no archives matched pattern %q", pattern)
			continue
		}
		for _, path := range matches {
			info, err := os.Stat(path)
			if err != nil {
				return fmt.Errorf("checking %q: %w", path, err)
			}
			if info.IsDir() {
				continue
			}
			nl, err := archiveNodeList(ctx, path, opts)
			if err != nil {
				return fmt.Errorf("scanning archive %q: %w", path, err)
			}
			doc.GetNodeList().Add(nl)
		}
	}
	return nil
}

// archiveNodeList extracts one tarball and scans its contents into a
// node list rooted at the archive's package node.
func archiveNodeList(ctx context.Context, tarPath string, opts *Options) (*sbom.NodeList, error) {
	if !isTarball(tarPath) {
		return nil, fmt.Errorf("%q: only tar archives (.tar, .tar.gz, .tgz) are supported", tarPath)
	}
	tmp, err := os.MkdirTemp("", "bom-archive-")
	if err != nil {
		return nil, fmt.Errorf("creating extraction directory: %w", err)
	}
	defer os.RemoveAll(tmp)
	if err := extractTarball(tarPath, tmp); err != nil {
		return nil, err
	}

	nl, err := treeNodeList(ctx, tmp, filepath.Base(tarPath), opts)
	if err != nil {
		return nil, err
	}

	// The package node represents the archive: it records the file it
	// was generated from and the checksums of the artifact itself, as
	// the legacy generator did.
	root := nl.GetNodeByID(nl.GetRootElements()[0])
	if root == nil {
		return nil, fmt.Errorf("no root node after scanning %q", tarPath)
	}
	if err := hashFileInto(root, tarPath); err != nil {
		return nil, err
	}
	root.FileName = tarPath
	return nl, nil
}

// isTarball reports whether path names a tar archive, compressed or
// not. These are the formats the legacy generator accepted, plus the
// .tgz shorthand.
func isTarball(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	return strings.HasSuffix(name, ".tar") ||
		strings.HasSuffix(name, ".tar.gz") ||
		strings.HasSuffix(name, ".tgz")
}

// extractTarball unpacks a tarball into dir. Only regular files are
// extracted: directory entries are recreated as needed, and symlinks
// and special files are dropped, matching what the file indexer
// records from a directory tree.
func extractTarball(tarPath, dir string) error {
	f, err := os.Open(tarPath)
	if err != nil {
		return fmt.Errorf("opening %q: %w", tarPath, err)
	}
	defer f.Close()

	// Compression is detected from the stream's magic number: gzipped
	// tarballs do not always carry a .gz extension.
	buffered := bufio.NewReader(f)
	var stream io.Reader = buffered
	if magic, err := buffered.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(buffered)
		if err != nil {
			return fmt.Errorf("opening gzip stream of %q: %w", tarPath, err)
		}
		defer gz.Close()
		stream = gz
	}

	tr := tar.NewReader(stream)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading tarball %q: %w", tarPath, err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := filepath.Clean(hdr.Name)
		if !filepath.IsLocal(name) {
			return fmt.Errorf("tarball %q holds an illegal path: %q", tarPath, hdr.Name)
		}
		target := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(target), os.FileMode(0o755)); err != nil {
			return fmt.Errorf("creating directory structure: %w", err)
		}
		if err := extractFile(target, tr, hdr.Size); err != nil {
			return fmt.Errorf("extracting %q: %w", hdr.Name, err)
		}
	}
}

// extractFile writes one entry's data to target, capped at the size
// its header declares so a crafted stream cannot expand past it.
func extractFile(target string, tr io.Reader, size int64) error {
	f, err := os.Create(target)
	if err != nil {
		return err
	}
	if _, err := io.CopyN(f, tr, size); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func tarWithEntries(t *testing.T, entries []*tar.Header) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.tar")
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	tw := tar.NewWriter(f)
	defer tw.Close()
	for _, hdr := range entries {
		require.NoError(t, tw.WriteHeader(hdr))
		if hdr.Typeflag == tar.TypeReg && hdr.Size > 0 {
			_, err := tw.Write(make([]byte, hdr.Size))
			require.NoError(t, err)
		}
	}
	return path
}

func TestExtractTarballTraversal(t *testing.T) {
	path := tarWithEntries(t, []*tar.Header{
		{Name: "../evil.txt", Mode: 0o644, Size: 4, Typeflag: tar.TypeReg},
	})
	err := extractTarball(path, t.TempDir())
	require.ErrorContains(t, err, "illegal path")
}

func TestExtractTarballSkipsSpecialFiles(t *testing.T) {
	path := tarWithEntries(t, []*tar.Header{
		{Name: "regular.txt", Mode: 0o644, Size: 4, Typeflag: tar.TypeReg},
		{Name: "link", Linkname: "regular.txt", Typeflag: tar.TypeSymlink},
		{Name: "subdir/", Mode: 0o755, Typeflag: tar.TypeDir},
	})
	dir := t.TempDir()
	require.NoError(t, extractTarball(path, dir))

	require.FileExists(t, filepath.Join(dir, "regular.txt"))
	require.NoFileExists(t, filepath.Join(dir, "link"),
		"symlinks are dropped, not materialized")
}

func TestIsTarball(t *testing.T) {
	for path, expected := range map[string]bool{
		"src.tar":     true,
		"src.tar.gz":  true,
		"src.TGZ":     true,
		"src.zip":     false,
		"srctar":      false,
		"src.tar.bz2": false,
	} {
		require.Equal(t, expected, isTarball(path), "path %q", path)
	}
}

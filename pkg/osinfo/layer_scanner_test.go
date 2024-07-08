/*
Copyright 2022 The Kubernetes Authors.

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

package osinfo

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"sigs.k8s.io/release-utils/hash"
)

func TestExtractFileFromTar(t *testing.T) {
	loss := newLayerScanner()

	file, err := os.CreateTemp("", "extract-")
	require.NoError(t, err)
	defer os.Remove(file.Name())

	require.NoError(t, loss.ExtractFileFromTar(
		"testdata/link-with-dots.tar.gz",
		"./etc/os-release",
		file.Name(),
	))

	checksum, err := hash.SHA256ForFile(file.Name())
	require.NoError(t, err)
	require.Equal(t, "c0c501c05a85ad53cbaf4028f75c078569dadda64ae8e793339096e05a3d98b0", checksum)

	file2, err := os.CreateTemp("", "extract-")
	require.NoError(t, err)
	defer os.Remove(file2.Name())

	require.NoError(t, loss.ExtractFileFromTar(
		"testdata/link-with-no-dots.tar.gz",
		"etc/os-release",
		file2.Name(),
	))

	checksum, err = hash.SHA256ForFile(file2.Name())
	require.NoError(t, err)
	require.Equal(t, "c0c501c05a85ad53cbaf4028f75c078569dadda64ae8e793339096e05a3d98b0", checksum)
}

func TestOSReleaseData(t *testing.T) {
	loss := newLayerScanner()
	data, err := loss.OSReleaseData("testdata/link-with-dots.tar.gz")
	require.NoError(t, err)
	require.NotEmpty(t, data)

	_, err = loss.OSReleaseData("testdata/nonexistent")
	require.Error(t, err)
}

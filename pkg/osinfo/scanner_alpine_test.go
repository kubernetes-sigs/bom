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

package osinfo

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseApkDB(t *testing.T) {
	ct := newAlpineScanner()

	// Test we have the expected packages
	pk, err := ct.ParseDB("testdata/apkdb")
	require.NoError(t, err)
	require.NotNil(t, pk)
	require.Len(t, *pk, 39)

	// Test package data
	require.Equal(t, "ca-certificates-bundle", (*pk)[0].Package)
	require.Equal(t, "20220614-r2", (*pk)[0].Version)
	require.Equal(t, "x86_64", (*pk)[0].Architecture)
	require.Equal(t, "MPL-2.0 AND MIT", (*pk)[0].License)
	require.Equal(t, "e07d34854d632d6491a45dd854cdabd177e990cc", (*pk)[0].Checksums["SHA1"])
}

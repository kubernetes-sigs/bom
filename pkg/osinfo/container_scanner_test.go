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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadOSPackages(t *testing.T) {
	layer, packages, err := ReadOSPackages([]string{
		"testdata/link-with-no-dots.tar.gz", // The first layer contains the OS Info
		"testdata/dpkg-layer1.tar.gz",       // The second layer contains the dpkg database
	})
	require.NoError(t, err)
	require.Equal(t, 1, layer)
	require.Len(t, *packages, 84)

	// No layers should yield no error
	_, _, err = ReadOSPackages([]string{})
	require.NoError(t, err)

	// While an invalid file shour err
	_, _, err = ReadOSPackages([]string{"testdata/nonexistent"})
	require.Error(t, err)
}

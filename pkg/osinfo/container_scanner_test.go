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

func TestReadDebianPackages(t *testing.T) {
	ct := ContainerScanner{}
	for _, tc := range []struct {
		layers      []string
		targetLayer int
		numPackages int
		shouldErr   bool
		nilPackages bool // Packages are nil when a layer has an unexptected OS
	}{
		// Two versions of DB in each layer
		{[]string{"testdata/dpkg-layer1.tar.gz", "testdata/dpkg-layer2.tar.gz"}, 1, 87, false, false},
		// Only one layer, one DB with 83 packages
		{[]string{"testdata/dpkg-layer1.tar.gz"}, 0, 83, false, false},
		// First layer no data, second with 87 packages
		{[]string{"testdata/link-with-no-dots.tar.gz", "testdata/dpkg-layer2.tar.gz"}, 1, 87, false, false},
		// The inverse
		{[]string{"testdata/dpkg-layer2.tar.gz", "testdata/link-with-no-dots.tar.gz"}, 0, 87, false, false},
		// One layer, no packages, unsupported OS
		{[]string{"testdata/link-with-no-dots.tar.gz"}, 0, 0, false, true},
	} {
		layerNum, packages, err := ct.ReadDebianPackages(tc.layers)
		require.Equal(t, tc.targetLayer, layerNum)
		if !tc.shouldErr {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}

		// Check if packages should be nil:
		if tc.nilPackages {
			require.Nil(t, packages)
		} else {
			require.NotNil(t, packages)
			require.Len(t, *packages, tc.numPackages)
		}
	}
}

func TestReadOSPackages(t *testing.T) {
	ct := ContainerScanner{}
	layer, packages, err := ct.ReadOSPackages([]string{
		"testdata/link-with-no-dots.tar.gz", // The first layer contains the OS Info
		"testdata/dpkg-layer1.tar.gz",       // The second layer contains the dpkg database
	})
	require.NoError(t, err)
	require.Equal(t, layer, 1)
	require.Len(t, *packages, 83)

	// No layers should yield no error
	_, _, err = ct.ReadOSPackages([]string{})
	require.NoError(t, err)

	// While an invalid file shour err
	_, _, err = ct.ReadOSPackages([]string{"testdata/nonexistent"})
	require.Error(t, err)
}

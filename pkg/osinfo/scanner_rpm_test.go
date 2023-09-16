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

func TestReadRpmPackages(t *testing.T) {
	ct := newRPMScanner()
	for _, tc := range []struct {
		name        string
		layers      []string
		targetLayer int
		numPackages int
		shouldErr   bool
		nilPackages bool
	}{
		{
			name:        "no layers",
			layers:      []string{},
			targetLayer: 0,
			shouldErr:   false,
			nilPackages: true,
		},
		{
			name:        "one layer",
			layers:      []string{"testdata/rpmdb.tar.gz"},
			targetLayer: 0,
			numPackages: 7,
			shouldErr:   false,
			nilPackages: false,
		},
		{
			name:        "rpm db not found",
			layers:      []string{"testdata/dpkg-layer1.tar.gz"},
			targetLayer: 0,
			numPackages: 0,
			shouldErr:   false,
			nilPackages: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layerNum, packages, err := ct.ReadOSPackages(tc.layers)
			require.Equal(t, tc.targetLayer, layerNum)
			if !tc.shouldErr {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}

			if tc.nilPackages {
				require.Nil(t, packages)
			} else {
				require.NotNil(t, packages)
				require.Len(t, *packages, tc.numPackages)
			}
		})
	}
}

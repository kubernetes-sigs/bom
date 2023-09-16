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

func TestReadDistrolessPackages(t *testing.T) {
	sut := distrolessScanner{
		baseDistro: OSDebian,
		ls:         newLayerScanner(),
	}
	for _, tc := range []struct {
		testName         string
		layerFile        string
		expectedPackages int
		mustErr          bool
	}{
		{"sample-file", "testdata/distroless.tar", 3, false},
		{"non-distroless", "testdata/link-with-no-dots.tar.gz", 0, true},
	} {
		t.Run(tc.testName, func(t *testing.T) {
			layerNum, db, err := sut.ReadOSPackages([]string{tc.layerFile})
			if tc.mustErr {
				require.Error(t, err, tc.testName)
				return
			}
			require.NoError(t, err, tc.testName)
			require.NotNil(t, db, tc.testName)
			require.Equal(t, 0, layerNum, tc.testName)
			require.Len(t, *db, tc.expectedPackages, tc.testName)
		})
	}
}

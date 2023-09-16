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
	"fmt"
	"net/url"
	"strings"
	"testing"

	purl "github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/require"
)

func TestReadDebianPackages(t *testing.T) {
	ct := newDebianScanner()
	for _, tc := range []struct {
		layers      []string
		targetLayer int
		numPackages int
		shouldErr   bool
		nilPackages bool // Packages are nil when a layer has an unexptected OS
	}{
		// Two versions of DB in each layer
		{[]string{"testdata/dpkg-layer1.tar.gz", "testdata/dpkg-layer2.tar.gz"}, 1, 88, false, false},
		// Only one layer, one DB with 83 packages
		{[]string{"testdata/dpkg-layer1.tar.gz"}, 0, 84, false, false},
		// First layer no data, second with 87 packages
		{[]string{"testdata/link-with-no-dots.tar.gz", "testdata/dpkg-layer2.tar.gz"}, 1, 88, false, false},
		// The inverse
		{[]string{"testdata/dpkg-layer2.tar.gz", "testdata/link-with-no-dots.tar.gz"}, 0, 88, false, false},
		// One layer, no packages, unsupported OS
		{[]string{"testdata/link-with-no-dots.tar.gz"}, 0, 0, false, true},
	} {
		layerNum, packages, err := ct.ReadOSPackages(tc.layers)
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

func TestParseDpkDb(t *testing.T) {
	_, packages, err := ReadOSPackages([]string{
		"testdata/link-with-no-dots.tar.gz", // The first layer contains the OS Info
		"testdata/dpkg-layer1.tar.gz",       // The second layer contains the dpkg database
	})

	require.NoError(t, err)

	require.Equal(t, "bash", (*packages)[4].Package)
	require.Equal(t, "amd64", (*packages)[4].Architecture)
	require.Equal(t, "5.0-4", (*packages)[4].Version)
	require.Equal(t, "http://tiswww.case.edu/php/chet/bash/bashtop.html", (*packages)[4].HomePage)
	require.Equal(t, "Matthias Klose", (*packages)[4].MaintainerName)
	require.Equal(t, "doko@debian.org", (*packages)[4].MaintainerEmail)
}

func TestPackageURL(t *testing.T) {
	for _, tc := range []struct {
		dbe      PackageDBEntry
		expected string
	}{
		{
			// Emtpty db entry
			dbe:      PackageDBEntry{},
			expected: "",
		},
		{
			// Only package
			dbe:      PackageDBEntry{Package: "test"},
			expected: "",
		},
		{
			// Emtpty db entry
			dbe: PackageDBEntry{
				Package: "test", Namespace: "osname",
			},
			expected: "",
		},
		{
			// Tyoe missing
			dbe: PackageDBEntry{
				Package: "test", Version: "v1.0.0", Namespace: "osname",
			},
			expected: "",
		},
		{
			// Minimum elements
			dbe: PackageDBEntry{
				Package: "test", Version: "v1.0.0", Type: purl.TypeDebian, Namespace: "osname",
			},
			expected: "pkg:deb/osname/test@v1.0.0",
		},
		{
			// All but type
			dbe: PackageDBEntry{
				Package: "test", Version: "v1.0.0", Architecture: "amd64",
				Type: purl.TypeDebian, Namespace: "osname",
			},
			expected: "pkg:deb/osname/test@v1.0.0?arch=amd64",
		},
	} {
		p := tc.dbe.PackageURL()
		require.Equal(t, tc.expected, p)
		if p == "" {
			continue
		}
		parsed, err := url.Parse(p)
		require.NoError(t, err)
		require.Equal(t, "pkg", parsed.Scheme)
		require.True(t, strings.HasPrefix(p, fmt.Sprintf(
			"pkg:%s/%s/%s@%s", tc.dbe.Type, tc.dbe.Namespace,
			tc.dbe.Package, tc.dbe.Version,
		)))
		require.Equal(t, tc.dbe.Architecture, parsed.Query().Get("arch"))
	}
}

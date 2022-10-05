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

package spdx

import (
	"fmt"
	"testing"

	purl "github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/require"
)

func TestPurl(t *testing.T) {
	pkg := NewPackage()
	pkg.ExternalRefs = []ExternalRef{{
		Category: "PACKAGE-MANAGER",
		Type:     "purl",
		Locator:  "pkg:deb/debian/libtiff5@4.2.0-1?arch=amd64",
	}}

	require.NotNil(t, pkg.Purl())

	// Invalid
	pkg.ExternalRefs = []ExternalRef{{
		Category: "PACKAGE-MANAGER",
		Type:     "purl",
		Locator:  "pkg: lsa slkdj l lkjlsl kjsl l sl kjs",
	}}

	require.Nil(t, pkg.Purl())

	// Validate the purl fields
	pkg.ExternalRefs = []ExternalRef{{
		Category: "PACKAGE-MANAGER",
		Type:     "purl",
		Locator:  "pkg:deb/debian/libicu67@67.1-7?arch=s390x",
	}}

	p := pkg.Purl()
	require.NotNil(t, p)

	require.Equal(t, "deb", p.Type)
	require.Equal(t, "debian", p.Namespace)
	require.Equal(t, "libicu67", p.Name)
	require.Equal(t, "67.1-7", p.Version)
	require.Equal(t, map[string]string{"arch": "s390x"}, p.Qualifiers.Map())
}

func TestPurlMatches(t *testing.T) {
	for _, tc := range []struct {
		purl      string
		spec      purl.PackageURL
		mustMatch bool
	}{
		{
			// Exact same OCI purl
			purl: "pkg:oci/nginx@sha256:4ed64c2e0857ad21c38b98345ebb5edb01791a0a10b0e9e3d9ddde185cdbd31a?repository_url=index.docker.io%2Flibrary&tag=nginx",
			spec: purl.PackageURL{
				Type: "oci", Name: "nginx",
				Version: "sha256:4ed64c2e0857ad21c38b98345ebb5edb01791a0a10b0e9e3d9ddde185cdbd31a",
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					"repository_url": "index.docker.io/library",
					"tag":            "nginx",
				}),
			},
			mustMatch: true,
		},
		{
			// Empty spec matches
			purl:      "pkg:oci/nginx@sha256:4ed64c2e0857ad21c38b98345ebb5edb01791a0a10b0e9e3d9ddde185cdbd31a?repository_url=index.docker.io%2Flibrary&tag=nginx",
			spec:      purl.PackageURL{},
			mustMatch: true,
		},
		{
			// Different type
			purl: "pkg:oci/nginx@sha256:4ed64c2e0857ad21c38b98345ebb5edb01791a0a10b0e9e3d9ddde185cdbd31a?repository_url=index.docker.io%2Flibrary&tag=nginx",
			spec: purl.PackageURL{
				Type: "docker", Name: "nginx",
				Version: "sha256:4ed64c2e0857ad21c38b98345ebb5edb01791a0a10b0e9e3d9ddde185cdbd31a",
			},
			mustMatch: false,
		},
		{
			purl: "pkg:deb/debian/perl-base@5.32.1-4+deb11u2?arch=amd64",
			spec: purl.PackageURL{
				Type: "deb", Namespace: "debian", Name: "perl-base", Version: "5.32.1-4+deb11u2",
				Qualifiers: purl.QualifiersFromMap(map[string]string{"arch": "amd64"}),
			},
			mustMatch: true,
		},
		{
			purl: "pkg:deb/debian/perl-base@5.32.1-4+deb11u2?arch=amd64",
			spec: purl.PackageURL{
				Type: "deb", Namespace: "debian", Name: "perl-base", Version: "5.32.1-4+deb11u2",
			},
			mustMatch: true,
		},
		{
			purl: "pkg:deb/debian/perl-base@5.32.1-4+deb11u2?arch=amd64",
			spec: purl.PackageURL{
				Type: "deb", Namespace: "debian", Name: "perl-base",
			},
			mustMatch: true,
		},
		{
			purl: "pkg:deb/debian/perl-base@5.32.1-4+deb11u2?arch=amd64",
			spec: purl.PackageURL{
				Type: "deb", Namespace: "debian",
			},
			mustMatch: true,
		},
		{
			purl:      "pkg:deb/debian/perl-base@5.32.1-4+deb11u2?arch=amd64",
			spec:      purl.PackageURL{Type: "deb"},
			mustMatch: true,
		},
	} {
		sut := NewPackage()
		sut.ExternalRefs = append(sut.ExternalRefs, ExternalRef{
			Category: "PACKAGE-MANAGER",
			Type:     "purl",
			Locator:  tc.purl,
		})
		wildcardizePurl(&tc.spec)
		require.Equal(t, tc.mustMatch, sut.PurlMatches(&tc.spec), tc.spec)
	}
}

// The spec for searching has to have wildcards
func wildcardizePurl(purlSpec *purl.PackageURL) {
	if purlSpec.Type == "" {
		purlSpec.Type = "*"
	}

	if purlSpec.Name == "" {
		purlSpec.Name = "*"
	}

	if purlSpec.Version == "" {
		purlSpec.Version = "*"
	}

	if purlSpec.Namespace == "" {
		purlSpec.Namespace = "*"
	}
}

func genTestPackage() (p *Package) {
	p = NewPackage()
	p.Name = "testPackage"
	return p
}

func TestComputeVerificationCode(t *testing.T) {
	p := genTestPackage()
	p.FilesAnalyzed = true

	// If package has no files, it should return an empty code
	require.NoError(t, p.ComputeVerificationCode())
	require.Equal(t, "", p.VerificationCode)

	// Add bunch of files
	for _, s1 := range []string{
		"2dce2a1b847cf337770abcf2f5a23fdb4150826a",
		"637ca3c1d37083c3de7f5928b1cec99f4495adc7",
		"05dd7d2e432a28126fe7b41c7cc1458b2936af8d",
		"805914c62e61ef0e5c8a23b4a388adf9c7154845",
	} {
		f := NewFile()
		f.Name = s1 + ".txt"
		f.Checksum = map[string]string{"SHA1": s1}
		require.NoError(t, p.AddFile(f))
	}

	// Code should be generated correctly
	require.NoError(t, p.ComputeVerificationCode())
	require.Equal(t, "7772199fd355003bfd91c7d946404685da0c5bb0", p.VerificationCode)

	// A file without a checksum should make the sum fail
	f := NewFile()
	f.Name = "test.txt"
	require.NoError(t, p.AddFile(f))
	require.Error(t, p.ComputeVerificationCode())

	// If FilesAnalyzed is false, the code should be empty
	p.FilesAnalyzed = false
	require.NoError(t, p.ComputeVerificationCode())
	require.Equal(t, "", p.VerificationCode)
}

func TestComputeLicenseList(t *testing.T) {
	p := genTestPackage()
	p.FilesAnalyzed = true
	p.LicenseConcluded = "GPL-2.0-only"
	p.Name = "testPackage"

	licenses := []string{
		"Apache-2.0",
		"BSD-2-Clause",
		"Spencer-94",
		"Spencer-94",
		"Apache-2.0",
		"Apache-2.0",
		"Apache-2.0",
	}

	unique := []string{
		"Apache-2.0",
		"BSD-2-Clause",
		"Spencer-94",
	}

	for i, l := range licenses {
		f := NewFile()
		f.Name = fmt.Sprintf("file%d.txt", i)
		f.LicenseInfoInFile = l
		require.NoError(t, p.AddFile(f))
	}
	require.NoError(t, p.ComputeLicenseList())
	require.ElementsMatch(t, p.LicenseInfoFromFiles, unique)

	// FilesAnalyzed=false should not return a list
	p.FilesAnalyzed = false
	require.NoError(t, p.ComputeLicenseList())
	require.Empty(t, p.LicenseInfoFromFiles)

	noLicenses := []string{NONE}

	// Package License concluded must not filter into the
	// license list unless found in a file
	p = genTestPackage()
	p.FilesAnalyzed = true
	p.LicenseConcluded = "GPL-2.0-only"

	f := NewFile()
	f.Name = "file.txt"
	require.NoError(t, p.AddFile(f))
	require.NoError(t, p.ComputeLicenseList())
	require.Equal(t, noLicenses, p.LicenseInfoFromFiles)

	// Same with licenses concluded in files
	p = genTestPackage()
	p.FilesAnalyzed = true

	f = NewFile()
	f.Name = "file.txt"
	f.LicenseConcluded = "Apache-2.0"
	require.NoError(t, p.AddFile(f))
	require.NoError(t, p.ComputeLicenseList())
	require.Equal(t, noLicenses, p.LicenseInfoFromFiles)
}

func TestIsURL(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		given string
		isURL bool
	}{
		{"", false},
		{"/", false},
		{"/foo/bar", false},
		{"http://", false},
		{"http//foo.bar/baz", false},
		{"https://foo.bar", true},
		{"https://foo.bar/baz", true},
	} {
		res := isURL(tc.given)
		require.Equal(t, tc.isURL, res)
	}
}

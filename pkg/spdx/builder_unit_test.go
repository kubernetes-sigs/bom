/*
Copyright 2021 The Kubernetes Authors.

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
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"sigs.k8s.io/bom/pkg/license"
)

var testConfig = `---
namespace: http://www.example.com/
license: Apache-2.0
name: bom-test
creator:
    person: Kubernetes Release Managers (release-managers@kubernetes.io)
    tool: bom
external-docs:
    - id: source-bom
      uri: https://example.com/source.spdx
      checksums:
        SHA1: 0123456789abcdef0123456789abcdef01234567
externalDocRefs:
    - id: legacy-bom
      uri: https://example.com/legacy.spdx
      checksums:
        SHA1: "1234567890123456789012345678901234567890"
artifacts:
    - type: directory
      source: .
      license: Apache-2.0
      gomodules: true
    - type: file
      source: ./SECURITY.md
    - type: image
      source: registry.k8s.io/kube-apiserver:v1.22.0-alpha.2
    - type: docker-archive
      source: tmp/sample-images/kube-apiserver.tar
`

func TestYAMLParse(t *testing.T) {
	opts := &DocGenerateOptions{}
	impl := defaultDocBuilderImpl{}
	f, err := os.CreateTemp("", "*.yaml")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	require.NoError(t, os.WriteFile(f.Name(), []byte(testConfig), os.FileMode(0o644)))

	require.NoError(t, impl.ReadYamlConfiguration(f.Name(), opts))

	require.Len(t, opts.Images, 1)
	require.Len(t, opts.Files, 1)
	require.Len(t, opts.Tarballs, 1)
	require.Len(t, opts.Directories, 1)

	require.Equal(t, "./SECURITY.md", opts.Files[0])
	require.Equal(t, "registry.k8s.io/kube-apiserver:v1.22.0-alpha.2", opts.Images[0])
	require.Equal(t, ".", opts.Directories[0])
	require.Equal(t, "tmp/sample-images/kube-apiserver.tar", opts.Tarballs[0])

	require.Equal(t, "Kubernetes Release Managers (release-managers@kubernetes.io)", opts.CreatorPerson)
	require.Equal(t, "http://www.example.com/", opts.Namespace)
	require.Equal(t, "bom-test", opts.Name)
	require.Equal(t, "Apache-2.0", opts.License)
	require.Equal(t, []ExternalDocumentRef{{
		ID:        "source-bom",
		URI:       "https://example.com/source.spdx",
		Checksums: map[string]string{"SHA1": "0123456789abcdef0123456789abcdef01234567"},
	}, {
		ID:        "legacy-bom",
		URI:       "https://example.com/legacy.spdx",
		Checksums: map[string]string{"SHA1": "1234567890123456789012345678901234567890"},
	}}, opts.ExternalDocumentRef)
}

func TestValidateLicenseListVersion(t *testing.T) {
	opts := &DocGenerateOptions{Files: []string{"file"}}
	for ver, expected := range map[string]string{"": "3.28", "v3.28.0": "3.28", "3.21": "3.21", "v3.20": "3.20"} {
		opts.LicenseListVersion = ver
		require.NoError(t, opts.Validate(), "version %q", ver)
		got, err := licenseListVersion(ver)
		require.NoError(t, err)
		require.Equal(t, expected, got)
	}
	for _, ver := range []string{"latest", "LATEST"} {
		opts.LicenseListVersion = ver
		require.NoError(t, opts.Validate(), "version %q", ver)
		require.Equal(t, license.DefaultCatalogOpts.Version, opts.LicenseListVersion, "version %q", ver)
	}
	for _, ver := range []string{"foo", "v3.x"} {
		opts.LicenseListVersion = ver
		require.ErrorContains(t, opts.Validate(), "parsing license list version", "version %q", ver)
	}
}

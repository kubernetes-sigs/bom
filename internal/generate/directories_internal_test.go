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
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"
)

func TestStripGoDirhashes(t *testing.T) {
	sha256Key := int32(sbom.HashAlgorithm_SHA256)
	goDep := &sbom.Node{
		Id:   "go-dep",
		Type: sbom.Node_PACKAGE,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): "pkg:golang/example.com/dep@v1.0.0",
		},
		Hashes: map[int32]string{
			sha256Key:                      "dirhash-not-a-digest",
			int32(sbom.HashAlgorithm_SHA1): "unrelated",
		},
	}
	otherPkg := &sbom.Node{
		Id:   "npm-dep",
		Type: sbom.Node_PACKAGE,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): "pkg:npm/leftpad@1.0.0",
		},
		Hashes: map[int32]string{sha256Key: "real-digest"},
	}
	file := &sbom.Node{
		Id:     "a-file",
		Type:   sbom.Node_FILE,
		Hashes: map[int32]string{sha256Key: "real-file-digest"},
	}

	nl := &sbom.NodeList{Nodes: []*sbom.Node{goDep, otherPkg, file}}
	stripGoDirhashes(nl)

	require.NotContains(t, goDep.GetHashes(), sha256Key, "go dirhash must be dropped")
	require.Contains(t, goDep.GetHashes(), int32(sbom.HashAlgorithm_SHA1), "other hashes survive")
	require.Equal(t, "real-digest", otherPkg.GetHashes()[sha256Key], "non-go packages keep hashes")
	require.Equal(t, "real-file-digest", file.GetHashes()[sha256Key], "files keep hashes")
}

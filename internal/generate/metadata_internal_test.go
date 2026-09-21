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

func TestDocumentTypes(t *testing.T) {
	types := func(source, analyzed bool) []sbom.DocumentType_SBOMType {
		dts := documentTypes(source, analyzed)
		ret := make([]sbom.DocumentType_SBOMType, 0, len(dts))
		for _, dt := range dts {
			ret = append(ret, dt.GetType())
		}
		return ret
	}
	require.Empty(t, types(false, false))
	require.Equal(t, []sbom.DocumentType_SBOMType{sbom.DocumentType_SOURCE}, types(true, false))
	require.Equal(t, []sbom.DocumentType_SBOMType{sbom.DocumentType_ANALYZED}, types(false, true))
	require.Equal(t,
		[]sbom.DocumentType_SBOMType{sbom.DocumentType_SOURCE, sbom.DocumentType_ANALYZED},
		types(true, true),
	)
}

func TestFilePurposes(t *testing.T) {
	for _, tc := range []struct {
		fileTypes []string
		expected  []sbom.Purpose
	}{
		{[]string{"SOURCE"}, []sbom.Purpose{sbom.Purpose_SOURCE}},
		{[]string{"TEXT", "DOCUMENTATION"}, []sbom.Purpose{sbom.Purpose_DOCUMENTATION}},
		{[]string{"ARCHIVE"}, []sbom.Purpose{sbom.Purpose_ARCHIVE}},
		{[]string{"IMAGE"}, []sbom.Purpose{sbom.Purpose_DATA}},
		{[]string{"AUDIO"}, []sbom.Purpose{sbom.Purpose_DATA}},
		// Object files, static libraries and scripts are APPLICATION
		// as well as executables.
		{[]string{"BINARY", "APPLICATION"}, nil},
		{[]string{"TEXT"}, nil},
		{[]string{"OTHER"}, nil},
		{nil, nil},
	} {
		require.Equal(t, tc.expected, filePurposes(tc.fileTypes), "file types %v", tc.fileTypes)
	}
}

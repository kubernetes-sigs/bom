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
	"slices"

	"github.com/protobom/protobom/pkg/sbom"
)

// documentTypes returns the kinds of SBOM a run produces: scanned
// directories and extracted archives describe source code, while
// images and files are analyzed after the fact. A run that found both
// is of both kinds, one that found nothing of neither.
func documentTypes(source, analyzed bool) []*sbom.DocumentType {
	var types []*sbom.DocumentType
	if source {
		types = append(types, &sbom.DocumentType{Type: sbom.DocumentType_SOURCE.Enum()})
	}
	if analyzed {
		types = append(types, &sbom.DocumentType{Type: sbom.DocumentType_ANALYZED.Enum()})
	}
	return types
}

// filePurposes derives the purpose of a file from its SPDX 2 file type
// labels, for the labels that say what a file is for. Others, like
// APPLICATION, which the file type detection assigns to object files,
// static libraries and scripts as well as to executables, leave the
// purpose unset. It replaces the SOURCE purpose unpack's file indexer
// assigns every file it indexes, whatever its content.
func filePurposes(fileTypes []string) []sbom.Purpose {
	switch {
	case slices.Contains(fileTypes, "SOURCE"):
		return []sbom.Purpose{sbom.Purpose_SOURCE}
	case slices.Contains(fileTypes, "DOCUMENTATION"):
		return []sbom.Purpose{sbom.Purpose_DOCUMENTATION}
	case slices.Contains(fileTypes, "ARCHIVE"):
		return []sbom.Purpose{sbom.Purpose_ARCHIVE}
	case slices.Contains(fileTypes, "IMAGE"), slices.Contains(fileTypes, "AUDIO"):
		return []sbom.Purpose{sbom.Purpose_DATA}
	default:
		return nil
	}
}

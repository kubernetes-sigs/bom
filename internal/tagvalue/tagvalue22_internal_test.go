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

package tagvalue

import (
	"testing"

	"github.com/spdx/tools-golang/spdx/v2/common"
	v2_2 "github.com/spdx/tools-golang/spdx/v2/v2_2"
	"github.com/stretchr/testify/require"
)

func TestDowngradeDocument(t *testing.T) {
	doc := &v2_2.Document{
		Packages: []*v2_2.Package{{
			PackageName: "test",
			PackageChecksums: []common.Checksum{
				{Algorithm: common.SHA256, Value: "aa"},
				{Algorithm: common.BLAKE3, Value: "bb"},
				{Algorithm: common.SHA3_256, Value: "cc"},
			},
		}},
		Files: []*v2_2.File{{
			FileName: "test.txt",
			Checksums: []common.Checksum{
				{Algorithm: common.SHA1, Value: "dd"},
				{Algorithm: common.ADLER32, Value: "ee"},
			},
		}},
	}
	downgradeDocument(doc)

	// Algorithms 2.3 introduced are dropped, 2.2 ones are kept.
	require.Equal(t,
		[]common.Checksum{{Algorithm: common.SHA256, Value: "aa"}},
		doc.Packages[0].PackageChecksums,
	)
	require.Equal(t,
		[]common.Checksum{{Algorithm: common.SHA1, Value: "dd"}},
		doc.Files[0].Checksums,
	)

	// Fields required in 2.2 are backfilled.
	require.Equal(t, noassertion, doc.Packages[0].PackageDownloadLocation)
	require.Equal(t, noassertion, doc.Packages[0].PackageLicenseConcluded)
	require.Equal(t, noassertion, doc.Packages[0].PackageLicenseDeclared)
	require.Equal(t, noassertion, doc.Packages[0].PackageCopyrightText)
	require.Equal(t, noassertion, doc.Files[0].LicenseConcluded)
	require.Equal(t, []string{noassertion}, doc.Files[0].LicenseInfoInFiles)
	require.Equal(t, noassertion, doc.Files[0].FileCopyrightText)
}

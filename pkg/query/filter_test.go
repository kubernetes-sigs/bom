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

package query

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/bom/pkg/spdx"
)

func testPackages() map[string]*spdx.Package {
	pks := map[string]*spdx.Package{}
	for i, s := range []string{"packageOne", "packageTwo"} {
		p := spdx.NewPackage()
		p.ID = s
		p.Name = fmt.Sprintf("gcr.io/puerco-chainguard/images/%s:v9.0.2-buster", s)
		dg := "sha256:4ed64c2e0857ad21c38b98345ebb5edb01791a0a10b0e9e3d9ddde185cdbd31a" //nolint: gosec
		repo := "index.docker.io%2Flibrary"
		if i == 1 {
			dg = "sha256:c0d8e30ad4f13b5f26794264fe057c488c72a5112978b1c24f3940dfaf69368a" //nolint: gosec
			repo = "gcr.io%2Fproject"
		}
		p.ExternalRefs = []spdx.ExternalRef{
			{
				Category: spdx.CatPackageManager,
				Type:     "purl",
				Locator: fmt.Sprintf(
					"pkg:oci/%s@%s?repository_url=%s&tag=nginx", s, dg, repo,
				),
			},
		}
		pks[s] = p
	}
	subFile := spdx.NewFile()
	subFile.ID = "subfile1"
	subFile.Name = "subfile1.txt"
	subFile.FileName = "subfile1.txt"
	pks["packageTwo"].AddRelationship(&spdx.Relationship{
		Type: "",
		Peer: subFile,
	})
	return pks
}

func testFiles() map[string]*spdx.File {
	files := map[string]*spdx.File{}
	for _, s := range []string{"file1.txt", "file2.txt"} {
		f := spdx.NewFile()
		f.ID = s
		f.Name = s
		f.FileName = s
		files[s] = f
	}
	return files
}

func testFilterResults() FilterResults {
	fr := FilterResults{
		Objects: map[string]spdx.Object{},
	}

	for _, o := range testFiles() {
		fr.Objects[o.SPDXID()] = o
	}

	for _, o := range testPackages() {
		fr.Objects[o.SPDXID()] = o
	}
	return fr
}

func TestDepth(t *testing.T) {
	fr := testFilterResults()
	newResults := fr.Apply(&DepthFilter{TargetDepth: 1})
	require.NotNil(t, newResults)
	require.Len(t, newResults.Objects, 1)
	for id, o := range newResults.Objects {
		require.Equal(t, o.SPDXID(), id)
		require.Equal(t, id, "subfile1")
	}

	fr2 := testFilterResults()
	// At level 0, we get the top elements in the testset
	fr2.Apply(&DepthFilter{TargetDepth: 0})
	require.NotNil(t, fr2.Objects)
	require.NoError(t, fr2.Error)
	require.Len(t, fr2.Objects, 4)

	// Beyond, we should not find more elemtns
	fr3 := testFilterResults()
	fr3.Apply(&DepthFilter{TargetDepth: 2})
	require.NotNil(t, fr3.Objects)
	require.NoError(t, fr3.Error)
	require.Len(t, fr3.Objects, 0)
}

func TestName(t *testing.T) {
	fr := testFilterResults()
	newResults := fr.Apply(&NameFilter{Pattern: "subfile"})
	require.Len(t, newResults.Objects, 1)

	// Match the two image packages
	fr = testFilterResults()
	newResults = fr.Apply(&NameFilter{Pattern: "puerco-chainguard"})
	require.Len(t, newResults.Objects, 2)
}

func TestPurl(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		num     int
		mustErr bool
		descr   string
	}{
		{"pkg:oci/*/*", 2, false, "match by type"},
		{"pkg:oci/*/packageOne", 1, false, "match by name"},
		{"sdlkfjlskdjf", 4, true, "invalid purl"},
		{"pkg:oci/*/*?repository_url=gcr.io%2Fproject", 1, false, "match by qualifiers"},
		{"pkg:oci/*/*?repository_url=index.docker.io%2Flibrary", 1, false, "match by qualifiers2"},
		{"pkg:oci/*/*@sha256:c0d8e30ad4f13b5f26794264fe057c488c72a5112978b1c24f3940dfaf69368a", 1, false, "match by version"},
	} {
		fr := testFilterResults()
		newResults := fr.Apply(&PurlFilter{Pattern: tc.pattern})
		if tc.mustErr {
			require.Error(t, newResults.Error)
		} else {
			require.NoError(t, newResults.Error)
		}
		require.Len(t, newResults.Objects, tc.num)
	}
}

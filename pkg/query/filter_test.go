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
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/bom/pkg/spdx"
)

func testPackages() map[string]*spdx.Package {
	pks := map[string]*spdx.Package{}
	for _, s := range []string{"packageOne", "packageTwo"} {
		p := spdx.NewPackage()
		p.ID = s
		pks[s] = p
	}
	subFile := spdx.NewFile()
	subFile.ID = "subfile1"
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

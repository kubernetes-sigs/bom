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
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/tagvalue"
	"github.com/stretchr/testify/require"
)

func createTempFile(name string) (*os.File, string, error) {
	dir, err := os.MkdirTemp("", "tests")
	if err != nil {
		return nil, "", err
	}
	file, err := os.CreateTemp(dir, name)
	if err != nil {
		return nil, "", err
	}

	return file, dir, err
}

func TestGetFileType(t *testing.T) {
	file, dir, err := createTempFile("temp.*.bat")
	require.NoError(t, err)

	fileType := getFileTypes(file.Name())

	require.Len(t, fileType, 2)
	require.Equal(t, []string{"BINARY", "APPLICATION"}, fileType)
	require.NoError(t, os.RemoveAll(dir))

	file, dir, err = createTempFile("honk.*.go")
	require.NoError(t, err)

	fileType = getFileTypes(file.Name())

	require.Len(t, fileType, 1)
	require.Equal(t, []string{"SOURCE"}, fileType)
	require.NoError(t, os.RemoveAll(dir))

	file, dir, err = createTempFile("honk.*.mp3")
	require.NoError(t, err)

	fileType = getFileTypes(file.Name())

	require.Len(t, fileType, 1)
	require.Equal(t, []string{"AUDIO"}, fileType)
	require.NoError(t, os.RemoveAll(dir))

	file, dir, err = createTempFile("say.*.honk")
	require.NoError(t, err)

	fileType = getFileTypes(file.Name())

	require.Len(t, fileType, 1)
	require.Equal(t, []string{"OTHER"}, fileType)
	require.NoError(t, os.RemoveAll(dir))
}

func TestFileRenderRelationships(t *testing.T) {
	pkg := NewPackage()
	pkg.Name = "example.com/app"

	f := NewFile()
	f.SetSPDXID("SPDXRef-File-app")
	f.Name = "app"
	f.Checksum = map[string]string{"SHA256": "abc"}
	f.AddRelationship(&Relationship{FullRender: true, Type: CONTAINS, Peer: pkg})

	out, err := f.Render()
	require.NoError(t, err)
	require.Contains(t, out, "FileName: app\n")
	require.NotContains(t, out, "PackageName:", "related objects render separately")

	out, err = f.RenderRelationships()
	require.NoError(t, err)
	require.NotEmpty(t, pkg.SPDXID(), "the check assigns missing peer IDs")
	require.Contains(t, out, "PackageName: example.com/app\n")
	require.Contains(t, out, "Relationship: SPDXRef-File-app CONTAINS "+pkg.SPDXID()+"\n")
}

// TestDocumentRenderFileOwnership parses the tag-value rendering of
// standalone files, one of them containing packages, with the SPDX
// tools: every file has to stay on the document level instead of
// landing in the package rendered before it.
func TestDocumentRenderFileOwnership(t *testing.T) {
	doc := NewDocument()
	doc.Name = "ownership"
	doc.Namespace = "https://sbom.k8s.io/test/ownership"

	stdlib := NewPackage()
	stdlib.SetSPDXID("SPDXRef-Package-stdlib")
	stdlib.Name = "stdlib"
	app := NewPackage()
	app.SetSPDXID("SPDXRef-Package-app")
	app.Name = "example.com/app"
	app.AddRelationship(&Relationship{FullRender: true, Type: DEPENDS_ON, Peer: stdlib})

	// The binary sorts between the other files, which render in ID
	// order regardless of the map order.
	for _, name := range []string{"a-readme", "b-binary", "c-notes"} {
		f := NewFile()
		f.SetSPDXID("SPDXRef-File-" + name)
		f.Name = name
		f.Checksum = map[string]string{"SHA1": "da39a3ee5e6b4b0d3255bfef95601890afd80709"}
		if name == "b-binary" {
			f.AddRelationship(&Relationship{FullRender: true, Type: CONTAINS, Peer: app})
		}
		require.NoError(t, doc.AddFile(f))
	}

	first, err := doc.Render()
	require.NoError(t, err)
	for range 10 {
		again, err := doc.Render()
		require.NoError(t, err)
		require.Equal(t, first, again, "rendering is deterministic")
	}

	parsed, err := tagvalue.Read(strings.NewReader(first))
	require.NoError(t, err)
	names := make([]string, 0, len(parsed.Files))
	for _, f := range parsed.Files {
		names = append(names, f.FileName)
	}
	require.Equal(t, []string{"a-readme", "b-binary", "c-notes"}, names)
	require.Len(t, parsed.Packages, 2)
	for _, p := range parsed.Packages {
		require.Empty(t, p.Files, "package %s owns no files", p.PackageName)
	}
	rels := make([]string, 0, len(parsed.Relationships))
	for _, r := range parsed.Relationships {
		rels = append(rels, fmt.Sprintf("%s %s %s",
			common.RenderDocElementID(r.RefA), r.Relationship, common.RenderDocElementID(r.RefB)))
	}
	require.Contains(t, rels, "SPDXRef-File-b-binary CONTAINS SPDXRef-Package-app")
	require.Contains(t, rels, "SPDXRef-Package-app DEPENDS_ON SPDXRef-Package-stdlib")
}

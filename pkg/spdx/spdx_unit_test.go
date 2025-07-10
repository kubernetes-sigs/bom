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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"sigs.k8s.io/release-utils/helpers"
)

func TestBuildIDString(t *testing.T) {
	cases := []struct {
		seeds    []string
		expected string
	}{
		{[]string{"1234"}, "1234"},
		{[]string{"abc"}, "abc"},
		{[]string{"ABC"}, "ABC"},
		{[]string{"ABC", "123"}, "ABC-123"},
		{[]string{"Hello:bye", "123"}, "Hello-bye-123"},
		{[]string{"Hello^bye", "123"}, "HelloC94bye-123"},
		{[]string{"Hello:bye", "123", "&-^%&$"}, "Hello-bye-123-C38-C94C37C38C36"},
	}
	for _, tc := range cases {
		require.Equal(t, tc.expected, buildIDString(tc.seeds...))
	}

	// If we do not pass any seeds, func should return an UUID
	// which is 36 chars long
	require.Len(t, buildIDString(), 36)
}

func TestUnitExtractTarballTmp(t *testing.T) {
	sut := NewSPDX()
	// Non existent files shoud error
	_, err := sut.ExtractTarballTmp("lsdjkflskdjfl")
	require.Error(t, err)

	// Lets test a zipped and unzipped tarball
	for _, tf := range []bool{true, false} {
		tarFile := writeTestTarball(t, tf)
		require.NotNil(t, tarFile)
		defer os.Remove(tarFile.Name())

		dir, err := sut.ExtractTarballTmp(tarFile.Name())
		require.NoError(t, err, "extracting file")
		defer os.RemoveAll(dir)

		require.True(t, helpers.Exists(filepath.Join(dir, "/text.txt")), "checking directory")
		require.True(t, helpers.Exists(filepath.Join(dir, "/subdir/text.txt")), "checking subdirectory")
		require.True(t, helpers.Exists(dir), "checking directory")
	}
}

func TestReadArchiveManifest(t *testing.T) {
	f, err := os.CreateTemp(os.TempDir(), "sample-manifest-*.json")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	require.NoError(t, os.WriteFile(
		f.Name(), []byte(sampleManifest), os.FileMode(0o644),
	), "writing test manifest file")

	sut := spdxDefaultImplementation{}
	_, err = sut.ReadArchiveManifest("laksdjlakjsdlkjsd")
	require.Error(t, err)
	manifest, err := sut.ReadArchiveManifest(f.Name())
	require.NoError(t, err)
	require.Equal(
		t, "386bcf5c63de46c7066c42d4ae1c38af0689836e88fed37d1dca2d484b343cf5.json",
		manifest.ConfigFilename,
	)
	require.Len(t, manifest.RepoTags, 1)
	require.Equal(t, "registry.k8s.io/kube-apiserver-amd64:v1.22.0-alpha.1", manifest.RepoTags[0])
	require.Len(t, manifest.LayerFiles, 3)
	for i, fname := range []string{
		"23e140cb8e03a12cba4ac571d9a7143cf5e2e9b72de3b33ce3243b4f7ad6a188/layer.tar",
		"48dd73ececdf0f52a174ad33a469145824713bd2b73c6257ce1ba8502003ad4e/layer.tar",
		"d397673d78556210baa112013c960cb95a3fd452e5c4a2ead2b26e5a458cd87f/layer.tar",
	} {
		require.Equal(t, fname, manifest.LayerFiles[i])
	}
}

func TestPackageFromTarball(t *testing.T) {
	tarFile := writeTestTarball(t, false)
	require.NotNil(t, tarFile)
	defer os.Remove(tarFile.Name())

	sut := spdxDefaultImplementation{}
	_, err := sut.PackageFromTarball(&Options{}, &TarballOptions{}, "lsdkjflksdjflk")
	require.Error(t, err)
	pkg, err := sut.PackageFromTarball(&Options{}, &TarballOptions{}, tarFile.Name())
	require.NoError(t, err)
	require.NotNil(t, pkg)

	require.NotNil(t, pkg.Checksum)
	_, ok := pkg.Checksum["SHA256"]
	require.True(t, ok, "checking if sha256 checksum is set")
	_, ok = pkg.Checksum["SHA512"]
	require.True(t, ok, "checking if sha512 checksum is set")
	require.Equal(t, "5e75826e1baf84d5c5b26cc8fc3744f560ef0288c767f1cbc160124733fdc50e", pkg.Checksum["SHA256"])
	require.Equal(t, "f3b48a64a3d9db36fff10a9752dea6271725ddf125baf7026cdf09a2c352d9ff4effadb75da31e4310bc1b2513be441c86488b69d689353128f703563846c97e", pkg.Checksum["SHA512"])
}

func TestExternalDocRef(t *testing.T) {
	cases := []struct {
		DocRef    ExternalDocumentRef
		StringVal string
	}{
		{ExternalDocumentRef{ID: "", URI: "", Checksums: map[string]string{}}, ""},
		{ExternalDocumentRef{ID: "", URI: "http://example.com/", Checksums: map[string]string{"SHA256": "d3b53860aa08e5c7ea868629800eaf78856f6ef3bcd4a2f8c5c865b75f6837c8"}}, ""},
		{ExternalDocumentRef{ID: "test-id", URI: "", Checksums: map[string]string{"SHA256": "d3b53860aa08e5c7ea868629800eaf78856f6ef3bcd4a2f8c5c865b75f6837c8"}}, ""},
		{ExternalDocumentRef{ID: "test-id", URI: "http://example.com/", Checksums: map[string]string{}}, ""},
		{
			ExternalDocumentRef{
				ID: "test-id", URI: "http://example.com/", Checksums: map[string]string{"SHA256": "d3b53860aa08e5c7ea868629800eaf78856f6ef3bcd4a2f8c5c865b75f6837c8"},
			},
			"DocumentRef-test-id http://example.com/ SHA256: d3b53860aa08e5c7ea868629800eaf78856f6ef3bcd4a2f8c5c865b75f6837c8",
		},
	}
	for _, tc := range cases {
		require.Equal(t, tc.StringVal, tc.DocRef.String())
	}
}

func TestExtDocReadSourceFile(t *testing.T) {
	// Create a known testfile
	f, err := os.CreateTemp("", "")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(f.Name(), []byte("Hellow World"), os.FileMode(0o644)))
	defer os.Remove(f.Name())

	ed := ExternalDocumentRef{}
	require.Error(t, ed.ReadSourceFile("/kjfhg/skjdfkjh"))
	require.NoError(t, ed.ReadSourceFile(f.Name()))
	require.NotNil(t, ed.Checksums)
	require.Len(t, ed.Checksums, 1)
	require.Equal(t, "5f341d31f6b6a8b15bc4e6704830bf37f99511d1", ed.Checksums["SHA1"])
}

func writeTestTarball(t *testing.T, zipped bool) *os.File {
	// Create a testdir
	fileprefix := "test-tar-*.tar"
	if zipped {
		fileprefix += ".gz"
	}
	tarFile, err := os.CreateTemp(os.TempDir(), fileprefix)
	require.NoError(t, err)

	tardata, err := base64.StdEncoding.DecodeString(testTar)
	require.NoError(t, err)

	if zipped {
		require.NoError(t, os.WriteFile(tarFile.Name(), tardata, os.FileMode(0o644)))
		return tarFile
	}

	reader := bytes.NewReader(tardata)
	zipreader, err := gzip.NewReader(reader)
	require.NoError(t, err)

	bindata, err := io.ReadAll(zipreader)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(
		tarFile.Name(), bindata, os.FileMode(0o644)), "writing test tar file",
	)
	return tarFile
}

func TestRelationshipRender(t *testing.T) {
	host := NewPackage()
	host.BuildID("TestHost")
	peer := NewFile()
	peer.BuildID("TestPeer")
	dummyref := "SPDXRef-File-6c0c16be41af1064ee8fd2328b17a0a778dd5e52"

	cases := []struct {
		Rel      Relationship
		MustErr  bool
		Rendered string
	}{
		{
			// Relationships with a full peer object have to render
			Relationship{FullRender: false, Type: DEPENDS_ON, Peer: peer},
			false, fmt.Sprintf("Relationship: %s DEPENDS_ON %s\n", host.SPDXID(), peer.SPDXID()),
		},
		{
			// Relationships with a remote reference
			Relationship{FullRender: false, Type: DEPENDS_ON, Peer: peer, PeerExtReference: "Remote"},
			false, fmt.Sprintf("Relationship: %s DEPENDS_ON DocumentRef-Remote:%s\n", host.SPDXID(), peer.SPDXID()),
		},
		{
			// Relationships without a full object, but
			// with a set reference must render
			Relationship{FullRender: false, PeerReference: dummyref, Type: DEPENDS_ON},
			false, fmt.Sprintf("Relationship: %s DEPENDS_ON %s\n", host.SPDXID(), dummyref),
		},
		{
			// Relationships without a object and without a set reference
			// must return an error
			Relationship{FullRender: false, Type: DEPENDS_ON}, true, "",
		},
		{
			// Relationships with a peer object withouth id should err
			Relationship{FullRender: false, Peer: &File{}, Type: DEPENDS_ON}, true, "",
		},
		{
			// Relationships with only a peer reference that should render
			// in full should err
			Relationship{FullRender: true, PeerReference: dummyref, Type: DEPENDS_ON}, true, "",
		},
		{
			// Relationships without a type should err
			Relationship{FullRender: false, PeerReference: dummyref}, true, "",
		},
	}

	for _, tc := range cases {
		res, err := tc.Rel.Render(host)
		if tc.MustErr {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
			require.Equal(t, tc.Rendered, res)
		}
	}

	// Full rednering should not be the same as non full render
	nonFullRender, err := cases[0].Rel.Render(host)
	require.NoError(t, err)
	cases[0].Rel.FullRender = true
	fullRender, err := cases[0].Rel.Render(host)
	require.NoError(t, err)
	require.NotEqual(t, nonFullRender, fullRender)

	// Finally, rendering with a host objectwithout an ID should err
	_, err = cases[0].Rel.Render(&File{})
	require.Error(t, err)
}

var testTar = `H4sICPIFo2AAA2hlbGxvLnRhcgDt1EsKwjAUBdCMXUXcQPuS5rMFwaEraDGgUFpIE3D5puAPRYuD
VNR7Jm+QQh7c3hQly44Sa/U4hdV0O8+YUKTJkLRCMhKk0zHX+VdjLA6h9pyz6Ju66198N3H+pYpy
iM1273P+Bm/lX4mUvyQlkP8cLvkHdwhFOIQMd4wBG6Oe5y/1Xf6VNhXjlGGXB3+e/yY2O9e2PV/H
xvnOBTcsF59eCmZT5Cz+yXT/5bX/pMb3P030fw4rlB8AAAAAAAAAAAAAAAAA4CccAXRRwL4AKAAA
`

var sampleManifest = `[{"Config":"386bcf5c63de46c7066c42d4ae1c38af0689836e88fed37d1dca2d484b343cf5.json","RepoTags":["registry.k8s.io/kube-apiserver-amd64:v1.22.0-alpha.1"],"Layers":["23e140cb8e03a12cba4ac571d9a7143cf5e2e9b72de3b33ce3243b4f7ad6a188/layer.tar","48dd73ececdf0f52a174ad33a469145824713bd2b73c6257ce1ba8502003ad4e/layer.tar","d397673d78556210baa112013c960cb95a3fd452e5c4a2ead2b26e5a458cd87f/layer.tar"]}]
`

func TestGetImageReferences(t *testing.T) {
	references, err := getImageReferences("registry.k8s.io/kube-apiserver:v1.23.0-alpha.3")
	images := map[string]struct {
		arch string
		os   string
	}{
		"registry.k8s.io/kube-apiserver@sha256:a82ca097e824f99bfb2b5107aa9c427633f9afb82afd002d59204f39ef81ae70": {"amd64", "linux"},
		"registry.k8s.io/kube-apiserver@sha256:2a11e07f916b5982d9a6e3bbf5defd66ad50359c00b33862552063beb6981aec": {"arm", "linux"},
		"registry.k8s.io/kube-apiserver@sha256:18f97b8c1c9b7b35dea7ba122d86e23066ce347aa8bb75b7346fed3f79d0ea21": {"arm64", "linux"},
		"registry.k8s.io/kube-apiserver@sha256:1a61b61491042e2b1e659c4d57d426d01d9467fb381404bff029be4d00ead519": {"ppc64le", "linux"},
		"registry.k8s.io/kube-apiserver@sha256:3e98f1591a5052791eec71d3c5f5d0fa913140992cb9e1d19fd80a158305c2ff": {"s390x", "linux"},
	}
	require.NoError(t, err)
	// This image should have 5 architectures
	require.Len(t, references.Images, 5)
	require.Equal(t, "application/vnd.docker.distribution.manifest.list.v2+json", references.MediaType)
	// INdices should have no platform
	require.Empty(t, references.Arch)
	require.Empty(t, references.OS)
	for _, refData := range references.Images {
		_, ok := images[refData.Digest]
		require.True(t, ok, "Image not found "+refData.Digest)
		require.Equal(t, images[refData.Digest].os, refData.OS)
		require.Equal(t, images[refData.Digest].arch, refData.Arch)
	}

	// Test a sha reference. This is the linux/ppc64le image
	singleRef := "registry.k8s.io/kube-apiserver@sha256:1a61b61491042e2b1e659c4d57d426d01d9467fb381404bff029be4d00ead519"
	references, err = getImageReferences(singleRef)
	require.NoError(t, err)
	require.Empty(t, references.Images)
	require.Equal(t, singleRef, references.Digest)
	require.Equal(t, "application/vnd.docker.distribution.manifest.v2+json", references.MediaType)
	require.Equal(t, "ppc64le", references.Arch)
	require.Equal(t, "linux", references.OS)

	// Tag with a single image. Image 1.0 is a single image
	references, err = getImageReferences("registry.k8s.io/pause:1.0")
	require.NoError(t, err)
	require.Empty(t, references.Images)
	require.Equal(t, "registry.k8s.io/pause@sha256:a78c2d6208eff9b672de43f880093100050983047b7b0afe0217d3656e1b0d5f", references.Digest)
	require.Equal(t, "application/vnd.docker.distribution.manifest.v2+json", references.MediaType)
	require.Equal(t, "amd64", references.Arch)
	require.Equal(t, "linux", references.OS)
}

func TestPullImagesToArchive(t *testing.T) {
	impl := spdxDefaultImplementation{}

	// First. If the tag does not represent an image, expect an error
	_, err := impl.PullImagesToArchive("registry.k8s.io/pause:0.0", "/tmp")
	require.Error(t, err)

	// Create a temp workdir
	dir, err := os.MkdirTemp("", "extract-image-")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	// The pause 1.0 image is a single image
	images, err := impl.PullImagesToArchive("registry.k8s.io/pause:1.0", dir)
	require.NoError(t, err)
	require.Equal(t, "registry.k8s.io/pause@sha256:a78c2d6208eff9b672de43f880093100050983047b7b0afe0217d3656e1b0d5f", images.Digest)
	require.Equal(t, "amd64", images.Arch)
	require.Equal(t, "linux", images.OS)
	require.Equal(t, "application/vnd.docker.distribution.manifest.v2+json", images.MediaType)
	require.Empty(t, images.Images) // This is an image, so no child images
	require.FileExists(t, filepath.Join(dir, "a78c2d6208eff9b672de43f880093100050983047b7b0afe0217d3656e1b0d5f.tar"))

	foundFiles := []string{}
	expectedFiles := []string{
		"sha256:350b164e7ae1dcddeffadd65c76226c9b6dc5553f5179153fb0e36b78f2a5e06",
		"a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4.tar.gz",
		"4964c72cd0245a7f77da38425dc98b472b2699ba6c49d5a9221fb32b972bc06b.tar.gz",
		"manifest.json",
	}
	tarFile, err := os.Open(filepath.Join(dir, "a78c2d6208eff9b672de43f880093100050983047b7b0afe0217d3656e1b0d5f.tar"))
	require.NoError(t, err)
	defer tarFile.Close()
	tarReader := tar.NewReader(tarFile)
	for {
		header, err := tarReader.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
		}
		if header == nil {
			break
		}
		foundFiles = append(foundFiles, header.Name)
	}
	require.Equal(t, expectedFiles, foundFiles)
}

func TestGetDirectoryTree(t *testing.T) {
	dir, err := os.MkdirTemp("", "dir-tree-")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	// Create a directory. This same array elements should be read back
	// from the temporary directory.
	files := []string{"test.txt", "sub1/test2.txt", "sub2/subsub/test3.txt"}
	path := ""
	for _, f := range files {
		path = filepath.Join(dir, f)
		dir := filepath.Dir(path)
		require.NoError(t, os.MkdirAll(dir, os.FileMode(0o0755)))
		require.NoError(t, os.WriteFile(path, []byte("test"), os.FileMode(0o644)))
	}

	impl := spdxDefaultImplementation{}
	readFiles, err := impl.GetDirectoryTree(dir)
	require.NoError(t, err)
	// Now, compare contents of th array is the same
	require.ElementsMatch(t, files, readFiles)
}

func TestIgnorePatterns(t *testing.T) {
	dir, err := os.MkdirTemp("", "dir-tree-")
	require.NoError(t, err)
	defer os.RemoveAll(dir)
	impl := spdxDefaultImplementation{}

	// First, a dir without a gitignore should return no patterns, but not err
	p, err := impl.IgnorePatterns(dir, []string{}, false)
	require.NoError(t, err)
	require.Empty(t, p)

	// If we pass an extra pattern, we should get it back
	p, err = impl.IgnorePatterns(dir, []string{".vscode"}, false)
	require.NoError(t, err)
	require.Len(t, p, 1)

	// Now put a gitignore and read it back
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, ".gitignore"),
		[]byte("# NFS\n.nfs*\n\n# OSX leaves these everywhere on SMB shares\n._*\n\n# OSX trash\n.DS_Store\n"),
		os.FileMode(0o755),
	))
	p, err = impl.IgnorePatterns(dir, nil, false)
	require.NoError(t, err)
	require.Len(t, p, 4)
}

func TestStructToString(t *testing.T) {
	testStruct := struct {
		A string
		B int
		C struct {
			D string
			E int
			F struct {
				G bool
			}
		}
	}{
		"hello", 1, struct {
			D string
			E int
			F struct {
				G bool
			}
		}{"", 2, struct {
			G bool
		}{false}},
	}
	require.Empty(t, structToString(1, false))
	require.Equal(t, `A: hello\nB: 1\nD: \nE: 2\nG: false\n`, structToString(testStruct, false))
	require.Equal(t, `A: hello\nB: 1\nE: 2\nG: false\n`, structToString(testStruct, true))
	require.Equal(t, `B: 1\nE: 2\n`, structToString(testStruct, true, "A", "G"))
}

func TestToDot(t *testing.T) {
	/*
		create the following package structure

					root
					 |
				-----------
				|         |
			node-1       node-2
			    |         |
			    -----------
			         |
			       leaf
	*/

	packageIDs := []string{"root", "node-1", "node-2", "leaf"}
	edges := []struct {
		p string
		c string
	}{
		{"root", "node-1"},
		{"root", "node-2"},
		{"node-1", "leaf"},
		{"node-2", "leaf"},
	}
	packages := map[string]*Package{}
	for _, id := range packageIDs {
		p := NewPackage()
		p.SetSPDXID(id)
		p.Name = id
		packages[id] = p
	}

	for _, edge := range edges {
		require.NoError(t, packages[edge.p].AddPackage(packages[edge.c]))
	}

	// split and sort by line since order here is not deterministic.
	expectedDot := strings.Split(`"root" [label="root" tooltip="ID: root\nName: root\nFilesAnalyzed: false\n" fontname="monospace"];
"root" -> "node-1";
"node-1" [label="node-1" tooltip="ID: node-1\nName: node-1\nFilesAnalyzed: false\n" fontname="monospace"];
"node-1" -> "leaf";
"leaf" [label="leaf" tooltip="ID: leaf\nName: leaf\nFilesAnalyzed: false\n" fontname="monospace"];
"root" -> "node-2";
"node-2" [label="node-2" tooltip="ID: node-2\nName: node-2\nFilesAnalyzed: false\n" fontname="monospace"];
"node-2" -> "leaf";
`, "\n")
	// run function
	actualDot := strings.Split(toDot(packages["root"], -1, &map[string]struct{}{}), "\n")
	slices.Sort(expectedDot)
	slices.Sort(actualDot)
	require.Equal(t, expectedDot, actualDot)
}

func TestRecursiveNameFilter(t *testing.T) {
	/*
		create the starting package structure

		root-p
		|
		|-target-p-0
		| |-sub-p-0
		|
		|-sub-p-1
		| |-target-p-1
		| |-sub-p-2
		|
		|-sub-p-3
	*/
	packageIDs := []string{"root-p"}
	for i := range 3 {
		packageIDs = append(packageIDs, fmt.Sprintf("target-p-%d", i))
	}
	for i := range 7 {
		packageIDs = append(packageIDs, fmt.Sprintf("sub-p-%d", i))
	}
	edges := []struct {
		p string
		c string
	}{
		{"root-p", "target-p-0"},
		{"root-p", "sub-p-1"},
		{"root-p", "sub-p-3"},
		{"target-p-0", "sub-p-0"},
		{"sub-p-1", "target-p-1"},
		{"sub-p-1", "sub-p-2"},
	}
	packages := map[string]*Package{}
	for _, id := range packageIDs {
		p := NewPackage()
		p.SetSPDXID(id)
		p.Name = strings.Join(strings.Split(id, "-")[:2], "-")
		packages[id] = p
	}

	for _, edge := range edges {
		require.NoError(t, packages[edge.p].AddPackage(packages[edge.c]))
	}

	/*
		create the expected package structure

		root-p
		|
		|-target-p-0
	*/
	ePackageIDs := []string{"root-p", "target-p-0"}
	eEdges := []struct {
		p string
		c string
	}{
		{"root-p", "target-p-0"},
	}
	ePackages := map[string]*Package{}
	for _, id := range ePackageIDs {
		p := NewPackage()
		p.SetSPDXID(id)
		p.Name = strings.Join(strings.Split(id, "-")[:2], "-")
		ePackages[id] = p
	}

	for _, edge := range eEdges {
		require.NoError(t, ePackages[edge.p].AddPackage(ePackages[edge.c]))
	}

	// filter the starting packages
	ok := recursiveNameFilter(
		"target-p",
		packages["root-p"],
		2,
		&map[string]bool{},
	)
	require.True(t, ok)

	// check filtered == expected
	require.Equal(t, ePackages["root-p"], packages["root-p"])
}

func TestRecursiveSearch(t *testing.T) {
	p := NewPackage()
	p.SetSPDXID("p-top")

	// Lets nest 3 packages
	packages := []*Package{}
	for i := range 3 {
		subp := NewPackage()
		subp.SetSPDXID(fmt.Sprintf("subpackage-%d", i))
		packages = append(packages, subp)
	}
	for i, sp := range packages {
		if i > 0 {
			require.NoError(t, packages[i-1].AddPackage(sp))
		}
	}
	require.NoError(t, p.AddPackage(packages[0]))

	// This functions searches 3 packages with the same prefix:
	checkSubPackages := func(p *Package, radix string) {
		for i := range 3 {
			require.NotNil(t, p.GetElementByID(fmt.Sprintf("%s-%d", radix, i)),
				"searching for "+radix,
			)
		}
	}

	checkSubPackages(p, "subpackage")
	// Non existent packages should not return an element
	require.Nil(t, p.GetElementByID("subpackage-10000000"))

	// Now bifurcating the document structure adding dependencies should
	// not alter those conditions.

	// Lets add 3 dependencies to one of the nested packages
	for i := range 3 {
		subp := NewPackage()
		subp.SetSPDXID(fmt.Sprintf("dep-%d", i))
		require.NoError(t, p.GetElementByID("subpackage-1").(*Package).AddPackage(subp)) //nolint: errcheck
	}

	// Same tests should still pass:
	checkSubPackages(p, "subpackage")
	// Non existent packages should not return an element
	require.Nil(t, p.GetElementByID("subpackage-10000000"))

	// But also dependencies should be found
	checkSubPackages(p, "dep")
}

func TestPurlFromImage(t *testing.T) {
	for _, tc := range []struct {
		info     ImageReferenceInfo
		expected string
	}{
		{
			ImageReferenceInfo{
				Digest:    "image@sha256:c183d71d4173c3148b73d17aba0f37c83ca8291d1f303d74a3fac4f5e1d01f57",
				Reference: "",
				Archive:   "",
				Arch:      "",
				OS:        "",
			},
			"pkg:oci/image@sha256%3Ac183d71d4173c3148b73d17aba0f37c83ca8291d1f303d74a3fac4f5e1d01f57?repository_url=index.docker.io%2Flibrary",
		},
		{
			ImageReferenceInfo{
				Digest:    "index.docker.io/library/nginx@sha256:c183d71d4173c3148b73d17aba0f37c83ca8291d1f303d74a3fac4f5e1d01f57",
				Reference: "index.docker.io/library/nginx@sha256:c183d71d4173c3148b73d17aba0f37c83ca8291d1f303d74a3fac4f5e1d01f57",
				Archive:   "",
				Arch:      "amd64",
				OS:        "darwin",
			},
			"pkg:oci/nginx@sha256%3Ac183d71d4173c3148b73d17aba0f37c83ca8291d1f303d74a3fac4f5e1d01f57?arch=amd64&os=darwin&repository_url=index.docker.io%2Flibrary",
		},
	} {
		impl := spdxDefaultImplementation{}
		p := impl.purlFromImage(&tc.info)
		require.Equal(t, tc.expected, p)
	}
}

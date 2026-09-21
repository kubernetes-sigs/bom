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

package sbomio

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"
)

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
		require.Equal(t, tc.isURL, isURL(tc.given), tc.given)
	}
}

// TestOpenNonConformant opens real-world documents that violate the
// SPDX specification in ways bom up to v0.7.1 read through: protobom
// rejects them, and the lenient retry repairs them.
func TestOpenNonConformant(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		path     string
		nodes    int
		checkPkg string
		supplier string
	}{
		{
			// SPDX 2.2 by apko: empty and free-form originators.
			path:     "../../pkg/spdx/testdata/images.spdx.json",
			nodes:    23,
			checkPkg: "alpine-baselayout-data",
			supplier: "Natanael Copa <ncopa@alpinelinux.org>",
		},
		{
			// An empty spdxVersion, identifiers without SPDXRef-.
			path:  "../../pkg/spdx/testdata/external-references.spdx.json",
			nodes: 1,
		},
	} {
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			doc, err := Open(tc.path)
			require.NoError(t, err)
			require.Len(t, doc.GetNodeList().GetNodes(), tc.nodes)

			// The source data describes the file, not the repaired copy.
			data, err := os.ReadFile(tc.path)
			require.NoError(t, err)
			sd := doc.GetMetadata().GetSourceData()
			require.Equal(t, int64(len(data)), sd.GetSize())
			require.Equal(t, fmt.Sprintf("%x", sha256.Sum256(data)), sd.GetHashes()[int32(sbom.HashAlgorithm_SHA256)])

			if tc.checkPkg == "" {
				return
			}
			var node *sbom.Node
			for _, n := range doc.GetNodeList().GetNodes() {
				if n.GetName() == tc.checkPkg {
					node = n
				}
			}
			require.NotNil(t, node)
			require.Len(t, node.GetOriginators(), 1)
			require.Equal(t, tc.supplier, node.GetOriginators()[0].GetName())
		})
	}
}

func TestSanitize(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		input  string
		output string
		fixes  int
	}{
		{
			name:  "conformant",
			input: `{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-2.3","packages":[{"originator":"Person: A","supplier":"NOASSERTION"}]}`,
		},
		{
			name:  "not SPDX",
			input: `{"bomFormat":"CycloneDX"}`,
		},
		{
			name:  "not JSON",
			input: "SPDXVersion: SPDX-2.3\n",
		},
		{
			name:   "no version",
			input:  `{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":""}`,
			output: `{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-2.3"}`,
			fixes:  1,
		},
		{
			name:  "trailing data",
			input: `{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":""} garbage`,
		},
		{
			name:  "second document",
			input: `{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":""}{}`,
		},
		{
			name:   "trailing space",
			input:  "{\"SPDXID\":\"SPDXRef-DOCUMENT\",\"spdxVersion\":\"\"}\n\n",
			output: `{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-2.3"}`,
			fixes:  1,
		},
		{
			name: "snippet ranges",
			input: `{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-2.3",
				"files":[{"SPDXID":"f"}],
				"snippets":[{"SPDXID":"SPDXRef-s","snippetFromFile":"f","ranges":[{"startPointer":{"reference":"f","offset":1},"endPointer":{"reference":"f","offset":2}}]}]}`,
			output: `{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-2.3",
				"files":[{"SPDXID":"SPDXRef-f"}],
				"snippets":[{"SPDXID":"SPDXRef-s","snippetFromFile":"SPDXRef-f","ranges":[{"startPointer":{"reference":"SPDXRef-f","offset":1},"endPointer":{"reference":"SPDXRef-f","offset":2}}]}]}`,
			fixes: 1,
		},
		{
			// Prefixing p would merge it with SPDXRef-p.
			name: "colliding identifiers",
			input: `{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-2.3",
				"packages":[{"SPDXID":"p"},{"SPDXID":"SPDXRef-p"},{"SPDXID":"q"}],
				"relationships":[{"spdxElementId":"p","relatedSpdxElement":"q"}]}`,
			output: `{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-2.3",
				"packages":[{"SPDXID":"p"},{"SPDXID":"SPDXRef-p"},{"SPDXID":"SPDXRef-q"}],
				"relationships":[{"spdxElementId":"p","relatedSpdxElement":"SPDXRef-q"}]}`,
			fixes: 1,
		},
		{
			name:   "actors",
			input:  `{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-2.2","packages":[{"originator":"","supplier":"Jane <j@example.com>"},{"originator":" "}]}`,
			output: `{"SPDXID":"SPDXRef-DOCUMENT","packages":[{"supplier":"Person: Jane <j@example.com>"},{}],"spdxVersion":"SPDX-2.2"}`,
			fixes:  2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out, fixes := sanitize([]byte(tc.input))
			require.Len(t, fixes, tc.fixes)
			if tc.output == "" {
				require.Nil(t, out)
				return
			}
			require.JSONEq(t, tc.output, string(out))
		})
	}
}

func TestSanitizeTagValue(t *testing.T) {
	t.Parallel()

	const input = `SPDXVersion: SPDX-2.3
SPDXID: SPDXRef-DOCUMENT
DocumentComment: <text>a comment
SPDXID: kept
</text>
Relationship: SPDXRef-DOCUMENT DESCRIBES pkg
Relationship: pkg CONTAINS DocumentRef-other:SPDXRef-x

PackageName: pkg
SPDXID: pkg
FileName: ./f
SPDXID: f
SnippetSPDXID: s
SnippetFromFileSPDXID: f
Annotator: Tool: x
SPDXREF: pkg
`
	const expected = `SPDXVersion: SPDX-2.3
SPDXID: SPDXRef-DOCUMENT
DocumentComment: <text>a comment
SPDXID: kept
</text>
Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-pkg
Relationship: SPDXRef-pkg CONTAINS DocumentRef-other:SPDXRef-x

PackageName: pkg
SPDXID: SPDXRef-pkg
FileName: ./f
SPDXID: SPDXRef-f
SnippetSPDXID: s
SnippetFromFileSPDXID: SPDXRef-f
Annotator: Tool: x
SPDXREF: SPDXRef-pkg
`
	out, fixes := sanitize([]byte(input))
	require.Len(t, fixes, 1)
	require.Equal(t, expected, string(out))

	out, fixes = sanitize([]byte(expected))
	require.Empty(t, fixes)
	require.Nil(t, out)

	out, fixes = sanitize([]byte("SPDXID: p\nSPDXID: SPDXRef-p\n"))
	require.Empty(t, fixes)
	require.Nil(t, out)
}

// TestOpenTagValueWithoutPrefix reads a tag-value document whose
// element identifiers lack the SPDXRef- prefix.
func TestOpenTagValueWithoutPrefix(t *testing.T) {
	t.Parallel()

	doc, err := Parse(strings.NewReader(tagValueDoc("SPDX-2.3", "pkg")))
	require.NoError(t, err)
	require.Len(t, doc.GetNodeList().GetNodes(), 1)
	require.Equal(t, []string{"pkg"}, doc.GetNodeList().GetRootElements())
}

// TestOpenSPDX21 reads SPDX 2.1 documents, which protobom does not
// detect, like SPDX 2.2 ones.
func TestOpenSPDX21(t *testing.T) {
	t.Parallel()

	doc, err := Parse(strings.NewReader(tagValueDoc("SPDX-2.1", "SPDXRef-pkg")))
	require.NoError(t, err)
	require.Len(t, doc.GetNodeList().GetNodes(), 1)

	doc, err = Parse(strings.NewReader(`{
  "spdxVersion": "SPDX-2.1",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "hello",
  "documentNamespace": "https://example.com/hello",
  "creationInfo": {"creators": ["Tool: x"], "created": "2021-08-26T01:46:00Z"},
  "packages": [{"name": "hello", "SPDXID": "SPDXRef-pkg", "downloadLocation": "NOASSERTION", "filesAnalyzed": false}],
  "documentDescribes": ["SPDXRef-pkg"]
}`))
	require.NoError(t, err)
	require.Len(t, doc.GetNodeList().GetNodes(), 1)

	_, err = Parse(strings.NewReader(tagValueDoc("SPDX-2.0", "SPDXRef-pkg")))
	require.Error(t, err)
}

func tagValueDoc(version, pkgID string) string {
	return `SPDXVersion: ` + version + `
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: hello
DocumentNamespace: https://example.com/hello
Creator: Tool: x
Created: 2021-08-26T01:46:00Z
Relationship: SPDXRef-DOCUMENT DESCRIBES ` + pkgID + `

PackageName: hello
SPDXID: ` + pkgID + `
PackageDownloadLocation: NOASSERTION
FilesAnalyzed: false
`
}

// TestTempFilesRemoved checks that the temporary copies of downloaded
// and piped documents are removed when buffering them fails.
func TestTempFilesRemoved(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	_, err := bufferToTemp(iotest.ErrReader(errors.New("broken pipe")))
	require.Error(t, err)

	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	_, err = Open(server.URL + "/sbom.spdx.json")
	require.Error(t, err)

	entries, err := os.ReadDir(tmp)
	require.NoError(t, err)
	require.Empty(t, entries)
}

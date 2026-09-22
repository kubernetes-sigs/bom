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

package bom_test

import (
	"bytes"
	"io"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/bom/pkg/bom"
	"sigs.k8s.io/bom/pkg/serialize"
	"sigs.k8s.io/bom/pkg/spdx"
)

// created matches the creation timestamps the serializers stamp.
var created = regexp.MustCompile(`("created": "|Created: )[0-9TZ:-]+`)

// normalize blanks out the creation timestamp of a rendered document
// and sorts its lines, without the commas separating JSON values: the
// legacy serializers do not render elements in a stable order.
func normalize(markup string) []string {
	lines := strings.Split(created.ReplaceAllString(markup, "${1}X"), "\n")
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], ",")
	}
	slices.Sort(lines)
	return lines
}

// TestWriteMatchesGenerate checks that Write renders a generated
// document exactly like bom generate does, and that Open reads the
// result back.
func TestWriteMatchesGenerate(t *testing.T) {
	const (
		name      = "write-test"
		namespace = "https://sbom.k8s.io/test/write"
		dir       = "../../test/golden/testdata/gomodule"
	)
	doc, err := bom.Generate(t.Context(), &bom.GenerateOptions{
		Name: name, Namespace: namespace, Directories: []string{dir}, Offline: true,
	})
	require.NoError(t, err)

	for _, tc := range []struct {
		format     bom.Format
		serializer serialize.Serializer
	}{
		{bom.FormatJSON, &serialize.JSON{}},
		{bom.FormatTagValue, &serialize.TagValue{}},
	} {
		t.Run(string(tc.format), func(t *testing.T) {
			var buf bytes.Buffer
			require.NoError(t, bom.Write(&buf, doc, &bom.WriteOptions{Format: tc.format}))

			// The legacy path bom generate takes is the reference. Its
			// serializers complete the document they render, so each
			// format needs a fresh one.
			//nolint:staticcheck // Deprecated, but what the CLI runs.
			ldoc, err := spdx.NewDocBuilder().Generate(&spdx.DocGenerateOptions{
				Name: name, Namespace: namespace, Directories: []string{dir}, Offline: true,
				ProcessGoModules: true,
			})
			require.NoError(t, err)
			expected, err := tc.serializer.Serialize(ldoc)
			require.NoError(t, err)
			require.Equal(t, normalize(expected), normalize(buf.String()))

			read, err := bom.Parse(io.NopCloser(strings.NewReader(buf.String())))
			require.NoError(t, err)
			require.Equal(t, name, read.GetMetadata().GetName())
			require.Len(t, read.GetNodeList().GetNodes(), len(doc.GetNodeList().GetNodes()))
		})
	}

	require.Error(t, bom.Write(io.Discard, doc, &bom.WriteOptions{Format: "yaml"}))
	require.Error(t, bom.Write(io.Discard, nil, nil))
}

// TestWriteKeepsCreators checks that Write keeps the organization a
// document credits and fills in bom's only when there is none.
func TestWriteKeepsCreators(t *testing.T) {
	doc := sbom.NewDocument()
	doc.GetMetadata().Name = "creators"
	doc.GetMetadata().Authors = []*sbom.Person{{Name: "Example Corp", IsOrg: true}}

	var buf bytes.Buffer
	require.NoError(t, bom.Write(&buf, doc, &bom.WriteOptions{Format: bom.FormatTagValue}))
	require.Contains(t, buf.String(), "Creator: Organization: Example Corp\n")
	require.NotContains(t, buf.String(), "Kubernetes Release Engineering")

	doc.GetMetadata().Authors = nil
	buf.Reset()
	require.NoError(t, bom.Write(&buf, doc, &bom.WriteOptions{Format: bom.FormatTagValue}))
	require.Contains(t, buf.String(), "Creator: Organization: Kubernetes Release Engineering\n")
}

func TestOpen(t *testing.T) {
	doc, err := bom.Open("../spdx/testdata/nginx.spdx")
	require.NoError(t, err)
	require.NotEmpty(t, doc.GetNodeList().GetNodes())

	_, err = bom.Open("testdata/does-not-exist.spdx.json")
	require.Error(t, err)
}

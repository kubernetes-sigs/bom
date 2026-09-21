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

package golden

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/bom/pkg/serialize"
	"sigs.k8s.io/bom/pkg/spdx"
)

var update = flag.Bool("update", false, "regenerate the golden files")

// fixedTime replaces the document creation timestamp so that the
// serialized output is stable.
var fixedTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func TestMain(m *testing.M) {
	logrus.SetLevel(logrus.ErrorLevel)
	os.Exit(m.Run())
}

func TestGoldenGenerate(t *testing.T) {
	for _, tc := range []struct {
		name string
		// slow cases initialize the license classifier
		slow    bool
		genopts func(t *testing.T) *spdx.DocGenerateOptions
	}{
		{
			// A directory holding a dependency-free Go module. Exercises
			// the directory scanner (checksums, license classification,
			// top-level license detection) and the go.mod code path. The
			// fixture has no go.sum, so no dependencies are resolved and
			// the network is never touched.
			name: "directory-gomodule",
			slow: true,
			genopts: func(*testing.T) *spdx.DocGenerateOptions {
				return &spdx.DocGenerateOptions{
					Directories:      []string{filepath.Join("testdata", "gomodule")},
					ProcessGoModules: true,
				}
			},
		},
		{
			// A directory holding a Go module with dependencies,
			// scanned offline so only the requirements its go.mod
			// declares are listed. The root package both holds files
			// and depends on packages; checkFileOwnership verifies that
			// every file lands under its package, while the ordering
			// fix itself is pinned by a unit test in pkg/spdx.
			name: "directory-gomodule-deps",
			slow: true,
			genopts: func(*testing.T) *spdx.DocGenerateOptions {
				return &spdx.DocGenerateOptions{
					Directories:      []string{filepath.Join("testdata", "gomodule-deps")},
					ProcessGoModules: true,
					Offline:          true,
				}
			},
		},
		{
			// A synthetic docker archive with a single Debian layer.
			// Exercises the image tarball scanner, the dpkg OS package
			// scanner and the normalization of the licenses Debian
			// copyright files declare.
			name: "image-archive",
			genopts: func(t *testing.T) *spdx.DocGenerateOptions {
				return &spdx.DocGenerateOptions{
					Tarballs:   []string{buildImageArchive(t)},
					ScanImages: true,
				}
			},
		},
		{
			// A plain file added to the document root.
			name: "single-file",
			genopts: func(*testing.T) *spdx.DocGenerateOptions {
				return &spdx.DocGenerateOptions{
					Files: []string{filepath.Join("testdata", "files", "hello.txt")},
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.slow && testing.Short() {
				t.Skip("initializes the license classifier, skipped with -short")
			}

			genopts := tc.genopts(t)
			genopts.Name = "bom-golden-" + tc.name
			genopts.Namespace = "https://sbom.k8s.io/golden/" + tc.name
			genopts.CreatorPerson = "Kubernetes Release Managers (release-managers@kubernetes.io)"
			genopts.LicenseListVersion = "v3.28.0" // the embedded license catalog

			doc, err := spdx.NewDocBuilder().Generate(genopts)
			require.NoError(t, err)

			// Pin the unstable document metadata.
			doc.Created = fixedTime
			doc.Creator.Tool = []string{"bom-golden-fixture"}

			tagValue, err := (&serialize.TagValue{}).Serialize(doc)
			require.NoError(t, err)
			checkFileOwnership(t, tagValue)
			checkGolden(t, tc.name+".spdx", canonicalTagValue(scrub(tagValue)))

			jsonDoc, err := (&serialize.JSON{}).Serialize(doc)
			require.NoError(t, err)
			checkGolden(t, tc.name+".spdx.json", canonicalJSON(t, scrub(jsonDoc)))
		})
	}
}

// checkGolden compares got against the golden file, or rewrites the
// golden file when the -update flag is set.
func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *update {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), os.FileMode(0o755)))
		require.NoError(t, os.WriteFile(path, []byte(got), os.FileMode(0o644)))
		return
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err, "reading golden file (run `go test ./test/golden -update` to create it)")
	require.Equal(t, string(want), got,
		"generated SBOM differs from %s — if the change is intentional, regenerate with `go test ./test/golden -update`", path)
}

// checkFileOwnership checks the element order of a raw tag-value
// document, which canonicalTagValue discards: in tag-value, a file
// belongs to the package listed last before it, so every file listed
// after a package must be one that package CONTAINS.
func checkFileOwnership(t *testing.T, tagValue string) {
	t.Helper()
	contains := map[string]struct{}{}
	for line := range strings.SplitSeq(tagValue, "\n") {
		if fields := strings.Fields(line); len(fields) == 4 && fields[0] == "Relationship:" && fields[2] == "CONTAINS" {
			contains[fields[1]+" "+fields[3]] = struct{}{}
		}
	}
	pkg, file := "", ""
	lastTag := ""
	for line := range strings.SplitSeq(tagValue, "\n") {
		tag, value, _ := strings.Cut(line, ": ")
		if tag == "SPDXID" {
			switch lastTag {
			case "PackageName":
				pkg = value
			case "FileName":
				file = value
				if pkg != "" {
					_, ok := contains[pkg+" "+file]
					require.True(t, ok, "file %s is listed after package %s, which does not contain it", file, pkg)
				}
			}
		}
		if tag != "" {
			lastTag = tag
		}
	}
}

// canonicalTagValue rewrites a tag-value document into a stable form:
// comment lines are dropped, blank-line-separated blocks after the
// document header are sorted, with the extracted licenses kept after
// the elements as tag-value requires, and all Relationship: lines are
// pulled into a single sorted section at the end. Parts of the generation
// pipeline emit elements and relationships in nondeterministic order
// (concurrent scans append as they finish), so the raw rendering is not
// directly comparable between runs.
func canonicalTagValue(in string) string {
	blocks := []string{}
	rels := []string{}
	cur := []string{}
	flush := func() {
		if len(cur) == 0 {
			return
		}
		blocks = append(blocks, strings.Join(cur, "\n"))
		cur = []string{}
	}
	for line := range strings.SplitSeq(in, "\n") {
		line = strings.TrimRight(line, " \t")
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, "Relationship:") {
			rels = append(rels, line)
			continue
		}
		cur = append(cur, line)
	}
	flush()
	if len(blocks) == 0 {
		return ""
	}
	// The first block is the document header; keep it first and sort
	// the element blocks after it, then the extracted licenses.
	elements, licenses := []string{}, []string{}
	for _, block := range blocks[1:] {
		if strings.HasPrefix(block, "LicenseID:") {
			licenses = append(licenses, block)
		} else {
			elements = append(elements, block)
		}
	}
	sort.Strings(elements)
	sort.Strings(licenses)
	blocks = append(append(blocks[:1], elements...), licenses...)
	sort.Strings(rels)
	if len(rels) > 0 {
		blocks = append(blocks, strings.Join(rels, "\n"))
	}
	return strings.Join(blocks, "\n\n") + "\n"
}

// canonicalJSON reindents a JSON document with all its arrays sorted by
// the serialized form of their elements, for the same reason as
// canonicalTagValue: element order in the output is not stable. It also
// pins creationInfo: unlike the tag-value renderer, the JSON serializer
// ignores the document's creator data and stamps its own tool version.
func canonicalJSON(t *testing.T, in string) string {
	t.Helper()
	var doc any
	require.NoError(t, json.Unmarshal([]byte(in), &doc))
	if root, ok := doc.(map[string]any); ok {
		if info, ok := root["creationInfo"].(map[string]any); ok {
			info["created"] = fixedTime.Format(time.RFC3339)
			if creators, ok := info["creators"].([]any); ok {
				for i, creator := range creators {
					if s, ok := creator.(string); ok && strings.HasPrefix(s, "Tool: bom") {
						creators[i] = "Tool: bom-golden-fixture"
					}
				}
			}
		}
	}
	out, err := json.MarshalIndent(canonicalValue(doc), "", "  ")
	require.NoError(t, err)
	return string(out) + "\n"
}

func canonicalValue(v any) any {
	switch value := v.(type) {
	case map[string]any:
		for k, e := range value {
			value[k] = canonicalValue(e)
		}
		return value
	case []any:
		for i, e := range value {
			value[i] = canonicalValue(e)
		}
		sort.Slice(value, func(i, j int) bool {
			return canonicalSortKey(value[i]) < canonicalSortKey(value[j])
		})
		return value
	default:
		return v
	}
}

func canonicalSortKey(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

var (
	tempPathRe = regexp.MustCompile(regexp.QuoteMeta(os.TempDir()) + `[\w./~-]*`)
	uuidRe     = regexp.MustCompile(`[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}`)
)

// scrub replaces unstable output fragments with fixed placeholders:
// paths under the system temp directory (the generators reference
// per-run temp locations) and UUIDs (legacy code paths append a random
// UUID to SPDX IDs when they get no usable seed).
func scrub(in string) string {
	in = tempPathRe.ReplaceAllString(in, "«TMPPATH»")
	return uuidRe.ReplaceAllString(in, "«UUID»")
}

type tarEntry struct {
	name string
	data []byte
}

// writeTar writes a reproducible tarball: fixed epoch timestamps, fixed
// modes and USTAR format, so that the archive checksum — which feeds the
// generated SPDX IDs — is identical on every run.
func writeTar(t *testing.T, path string, entries []tarEntry) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	tw := tar.NewWriter(f)
	for _, entry := range entries {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name:    entry.name,
			Mode:    0o644,
			Size:    int64(len(entry.data)),
			ModTime: time.Unix(0, 0).UTC(),
			Format:  tar.FormatUSTAR,
		}))
		_, err = tw.Write(entry.data)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
}

// layerFixture is the gzipped layer of the image archive fixture. It is
// committed rather than compressed at test time: the image digest
// covers the compressed layer, and compress/gzip output changes between
// Go releases. Running the tests with -update rebuilds it from the text
// fixtures in testdata/image.
var layerFixture = filepath.Join("testdata", "image", "layer.tar.gz")

// layerEntries returns the files of the image layer, read from the
// text fixtures in testdata/image.
func layerEntries(t *testing.T) []tarEntry {
	t.Helper()
	osRelease, err := os.ReadFile(filepath.Join("testdata", "image", "os-release"))
	require.NoError(t, err)
	dpkgStatus, err := os.ReadFile(filepath.Join("testdata", "image", "dpkg-status"))
	require.NoError(t, err)
	copyright, err := os.ReadFile(filepath.Join("testdata", "image", "base-files-copyright"))
	require.NoError(t, err)
	return []tarEntry{
		{name: "etc/os-release", data: osRelease},
		{name: "usr/share/doc/base-files/copyright", data: copyright},
		{name: "var/lib/dpkg/status", data: dpkgStatus},
	}
}

// readLayerFixture returns the compressed layer fixture and its
// uncompressed tarball. It fails when the fixture no longer holds the
// text fixtures, and under -update rebuilds it in that case only, so
// updating the golden files with another Go release leaves it alone.
func readLayerFixture(t *testing.T) (compressed, uncompressed []byte) {
	t.Helper()
	layerPath := filepath.Join(t.TempDir(), "layer.tar")
	writeTar(t, layerPath, layerEntries(t))
	layerData, err := os.ReadFile(layerPath)
	require.NoError(t, err)

	// A missing or unreadable fixture reads as empty, failing the
	// comparison below (or getting rebuilt under -update).
	read := func() (compressed, uncompressed []byte) {
		compressed, err := os.ReadFile(layerFixture)
		if err != nil {
			return nil, nil
		}
		gz, err := gzip.NewReader(bytes.NewReader(compressed))
		if err != nil {
			return compressed, nil
		}
		if uncompressed, err = io.ReadAll(gz); err != nil {
			return compressed, nil
		}
		return compressed, uncompressed
	}
	compressed, uncompressed = read()
	if *update && !bytes.Equal(layerData, uncompressed) {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, err := gz.Write(layerData)
		require.NoError(t, err)
		require.NoError(t, gz.Close())
		require.NoError(t, os.WriteFile(layerFixture, buf.Bytes(), os.FileMode(0o644)))
		compressed, uncompressed = read()
	}
	require.Equal(t, layerData, uncompressed,
		"%s is missing or out of date with the text fixtures, regenerate it with `go test ./test/golden -update`", layerFixture)
	return compressed, uncompressed
}

// buildImageArchive assembles a minimal docker-save style archive with a
// single Debian layer from the committed layer fixture.
func buildImageArchive(t *testing.T) string {
	t.Helper()
	compressed, uncompressed := readLayerFixture(t)

	// The config must declare the layer diff ids: without them the
	// go-containerregistry loader the engine reads archives with
	// treats the image as having no layers.
	config := fmt.Sprintf(
		`{"architecture":"amd64","os":"linux","config":{},"rootfs":{"type":"layers","diff_ids":["sha256:%x"]}}`,
		sha256.Sum256(uncompressed),
	)

	archivePath := filepath.Join(t.TempDir(), "bom-golden-image.tar")
	writeTar(t, archivePath, []tarEntry{
		{
			name: "config.json",
			data: []byte(config),
		},
		{
			name: "manifest.json",
			data: []byte(`[{"Config":"config.json","RepoTags":["registry.k8s.io/bom-golden:v1.0.0"],"Layers":["layer.tar.gz"]}]`),
		},
		{name: "layer.tar.gz", data: compressed},
	})
	return archivePath
}

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
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
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
			// A synthetic docker archive with a single Debian layer.
			// Exercises the image tarball scanner and the dpkg OS
			// package scanner.
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

// canonicalTagValue rewrites a tag-value document into a stable form:
// comment lines are dropped, blank-line-separated blocks after the
// document header are sorted, and all Relationship: lines are pulled
// into a single sorted section at the end. Parts of the generation
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
	// the element blocks after it.
	sort.Strings(blocks[1:])
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
// ignores the document's creation data and stamps time.Now() and its
// own tool version.
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
// per-run temp locations) and UUIDs (buildIDString appends a random
// UUID to SPDX IDs when it gets no usable seed, as happens for the OS
// packages scanned from image layers).
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

// buildImageArchive assembles a minimal docker-save style archive with a
// single Debian layer from the text fixtures in testdata/image.
func buildImageArchive(t *testing.T) string {
	t.Helper()
	osRelease, err := os.ReadFile(filepath.Join("testdata", "image", "os-release"))
	require.NoError(t, err)
	dpkgStatus, err := os.ReadFile(filepath.Join("testdata", "image", "dpkg-status"))
	require.NoError(t, err)

	dir := t.TempDir()
	layerPath := filepath.Join(dir, "layer.tar")
	writeTar(t, layerPath, []tarEntry{
		{name: "etc/os-release", data: osRelease},
		{name: "var/lib/dpkg/status", data: dpkgStatus},
	})
	layerData, err := os.ReadFile(layerPath)
	require.NoError(t, err)

	// The config must declare the layer diff ids: without them the
	// go-containerregistry loader the engine reads archives with
	// treats the image as having no layers.
	config := fmt.Sprintf(
		`{"architecture":"amd64","os":"linux","config":{},"rootfs":{"type":"layers","diff_ids":["sha256:%x"]}}`,
		sha256.Sum256(layerData),
	)

	archivePath := filepath.Join(dir, "bom-golden-image.tar")
	writeTar(t, archivePath, []tarEntry{
		{
			name: "config.json",
			data: []byte(config),
		},
		{
			name: "manifest.json",
			data: []byte(`[{"Config":"config.json","RepoTags":["registry.k8s.io/bom-golden:v1.0.0"],"Layers":["layer.tar"]}]`),
		},
		{name: "layer.tar", data: layerData},
	})
	return archivePath
}

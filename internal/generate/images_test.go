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

package generate_test

import (
	"archive/tar"
	"bytes"
	"io"
	"log"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/bom/internal/generate"
)

// fixtureImage assembles a one-layer Debian image from the golden
// harness's dpkg fixtures.
func fixtureImage(t *testing.T) v1.Image {
	t.Helper()
	osRelease, err := os.ReadFile("../../test/golden/testdata/image/os-release")
	require.NoError(t, err)
	dpkgStatus, err := os.ReadFile("../../test/golden/testdata/image/dpkg-status")
	require.NoError(t, err)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, entry := range []struct {
		name    string
		content []byte
	}{
		{"etc/os-release", osRelease},
		{"var/lib/dpkg/status", dpkgStatus},
	} {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name: entry.name,
			Mode: 0o644,
			Size: int64(len(entry.content)),
		}))
		_, err := tw.Write(entry.content)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())

	data := buf.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	})
	require.NoError(t, err)
	img, err := mutate.AppendLayers(empty.Image, layer)
	require.NoError(t, err)

	// The config is edited in place: replacing it wholesale would drop
	// the rootfs diff ids the tarball loader validates.
	cfg, err := img.ConfigFile()
	require.NoError(t, err)
	cfg = cfg.DeepCopy()
	cfg.Architecture = "amd64"
	cfg.OS = "linux"
	img, err = mutate.ConfigFile(img, cfg)
	require.NoError(t, err)
	return img
}

// imageChildren gathers the nodes the image node contains, split into
// structural layer nodes and packages.
func imageChildren(t *testing.T, nl *sbom.NodeList, imageID string) (layers, packages []*sbom.Node) {
	t.Helper()
	for _, edge := range nl.GetEdges() {
		if edge.GetFrom() != imageID || edge.GetType() != sbom.Edge_contains {
			continue
		}
		for _, id := range edge.GetTo() {
			node := nl.GetNodeByID(id)
			require.NotNil(t, node, "dangling edge target %q", id)
			if strings.HasPrefix(node.GetName(), "sha256:") {
				layers = append(layers, node)
			} else {
				packages = append(packages, node)
			}
		}
	}
	return layers, packages
}

func TestImageArchives(t *testing.T) {
	img := fixtureImage(t)
	tag, err := name.NewTag("registry.k8s.io/bom-test:v1.0.0")
	require.NoError(t, err)
	archive := filepath.Join(t.TempDir(), "image.tar")
	require.NoError(t, tarball.MultiWriteToFile(archive, map[name.Tag]v1.Image{tag: img}))

	doc, err := generate.Document(t.Context(), &generate.Options{
		ImageArchives: []string{archive},
	})
	require.NoError(t, err)

	nl := doc.GetNodeList()
	require.Len(t, nl.GetRootElements(), 1)
	root := nl.GetNodeByID(nl.GetRootElements()[0])
	require.NotNil(t, root)
	require.Equal(t, "Package-registry.k8s.io-bom-test-v1.0.0", root.GetId(),
		"image ids derive from the reference, not from unpack's uuids")
	require.Equal(t, tag.String(), root.GetName())
	require.Equal(t, "v1.0.0", root.GetVersion())
	require.Contains(t, string(root.Purl()), "pkg:oci/bom-test")

	layers, packages := imageChildren(t, nl, root.GetId())

	require.Len(t, layers, 1, "one structural node per layer")
	layer := layers[0]
	require.True(t,
		strings.HasPrefix(layer.GetId(), "Package-registry.k8s.io-bom-test-v1.0.0-sha256-"),
		"layer id %q seeds on the image name", layer.GetId())
	require.NotEmpty(t, layer.GetHashes()[int32(sbom.HashAlgorithm_SHA256)])
	for _, edge := range nl.GetEdges() {
		require.NotEqual(t, layer.GetId(), edge.GetFrom(), "layer nodes carry no packages")
	}

	names := make([]string, 0, len(packages))
	for _, pkg := range packages {
		names = append(names, pkg.GetName())
		require.True(t, strings.HasPrefix(string(pkg.Purl()), "pkg:deb/debian/"),
			"package %q purl %q", pkg.GetName(), pkg.Purl())
	}
	require.ElementsMatch(t, []string{"base-files", "libssl3"}, names,
		"the dpkg inventory reads from the squashed filesystem")
}

func TestImages(t *testing.T) {
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(srv.Close)
	host, err := url.Parse(srv.URL)
	require.NoError(t, err)

	img := fixtureImage(t)
	refStr := host.Host + "/bom-test:v1"
	ref, err := name.ParseReference(refStr)
	require.NoError(t, err)
	require.NoError(t, remote.Write(ref, img))

	doc, err := generate.Document(t.Context(), &generate.Options{
		Images: []string{refStr},
	})
	require.NoError(t, err)

	nl := doc.GetNodeList()
	require.Len(t, nl.GetRootElements(), 1)
	root := nl.GetNodeByID(nl.GetRootElements()[0])
	require.NotNil(t, root)
	require.Equal(t, refStr, root.GetName())
	require.True(t, strings.HasPrefix(root.GetId(), "Package-"), "id %q", root.GetId())

	layers, packages := imageChildren(t, nl, root.GetId())
	require.Len(t, layers, 1)
	require.Len(t, packages, 2)
}

func TestImagesOffline(t *testing.T) {
	_, err := generate.Document(t.Context(), &generate.Options{
		Images:  []string{"registry.example.com/anything:v1"},
		Offline: true,
	})
	require.ErrorContains(t, err, "offline")
}

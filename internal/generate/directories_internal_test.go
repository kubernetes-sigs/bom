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

package generate

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/modfile"
)

func TestStripGoDirhashes(t *testing.T) {
	sha256Key := int32(sbom.HashAlgorithm_SHA256)
	goDep := &sbom.Node{
		Id:   "go-dep",
		Type: sbom.Node_PACKAGE,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): "pkg:golang/example.com/dep@v1.0.0",
		},
		Hashes: map[int32]string{
			sha256Key:                      "dirhash-not-a-digest",
			int32(sbom.HashAlgorithm_SHA1): "unrelated",
		},
	}
	otherPkg := &sbom.Node{
		Id:   "npm-dep",
		Type: sbom.Node_PACKAGE,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): "pkg:npm/leftpad@1.0.0",
		},
		Hashes: map[int32]string{sha256Key: "real-digest"},
	}
	file := &sbom.Node{
		Id:     "a-file",
		Type:   sbom.Node_FILE,
		Hashes: map[int32]string{sha256Key: "real-file-digest"},
	}

	nl := &sbom.NodeList{Nodes: []*sbom.Node{goDep, otherPkg, file}}
	stripGoDirhashes(nl)

	require.NotContains(t, goDep.GetHashes(), sha256Key, "go dirhash must be dropped")
	require.Contains(t, goDep.GetHashes(), int32(sbom.HashAlgorithm_SHA1), "other hashes survive")
	require.Equal(t, "real-digest", otherPkg.GetHashes()[sha256Key], "non-go packages keep hashes")
	require.Equal(t, "real-file-digest", file.GetHashes()[sha256Key], "files keep hashes")
}

func TestStripPackageNameFileNames(t *testing.T) {
	npmDep := &sbom.Node{Id: "npm-dep", Type: sbom.Node_PACKAGE, Name: "leftpad", FileName: "leftpad"}
	tarball := &sbom.Node{Id: "tarball", Type: sbom.Node_PACKAGE, Name: "app", FileName: "app-1.0.0.tgz"}
	file := &sbom.Node{Id: "a-file", Type: sbom.Node_FILE, Name: "main.go", FileName: "main.go"}

	stripPackageNameFileNames(&sbom.NodeList{Nodes: []*sbom.Node{npmDep, tarball, file}})

	require.Empty(t, npmDep.GetFileName(), "a package name is no file name")
	require.Equal(t, "app-1.0.0.tgz", tarball.GetFileName())
	require.Equal(t, "main.go", file.GetFileName(), "files keep their names")
}

// Node identifiers shared by the pruning tests.
const (
	rootID   = "root"
	directID = "direct"
)

func TestKeepDirectDependencies(t *testing.T) {
	// root -> direct -> transitive, plus a file the root contains.
	nl := &sbom.NodeList{
		Nodes: []*sbom.Node{
			{Id: rootID, Type: sbom.Node_PACKAGE, Name: rootID},
			{Id: directID, Type: sbom.Node_PACKAGE, Name: directID},
			{Id: "transitive", Type: sbom.Node_PACKAGE, Name: "transitive"},
			{Id: "file", Type: sbom.Node_FILE, Name: "main.go"},
		},
		Edges: []*sbom.Edge{
			{Type: sbom.Edge_dependsOn, From: rootID, To: []string{directID}},
			{Type: sbom.Edge_dependsOn, From: directID, To: []string{"transitive"}},
			{Type: sbom.Edge_contains, From: rootID, To: []string{"file"}},
		},
		RootElements: []string{rootID},
	}

	keepDirectDependencies(nl)

	ids := make([]string, 0, len(nl.GetNodes()))
	for _, node := range nl.GetNodes() {
		ids = append(ids, node.GetId())
	}
	require.ElementsMatch(t, []string{rootID, directID, "file"}, ids,
		"only what the root reaches in one step survives")

	// The edge into the dropped node goes with it.
	for _, edge := range nl.GetEdges() {
		require.NotContains(t, edge.GetTo(), "transitive",
			"edges must not point at a removed node")
	}
}

// TestKeepDirectDependenciesDoesNotCascade pins the subtlety that
// makes this correct: a direct dependency must not act as a root and
// pull in its own dependencies.
func TestKeepDirectDependenciesDoesNotCascade(t *testing.T) {
	nl := &sbom.NodeList{
		Nodes: []*sbom.Node{
			{Id: "a", Type: sbom.Node_PACKAGE},
			{Id: "b", Type: sbom.Node_PACKAGE},
			{Id: "c", Type: sbom.Node_PACKAGE},
			{Id: "d", Type: sbom.Node_PACKAGE},
		},
		Edges: []*sbom.Edge{
			// Ordered so a naive walk would reach c and then d.
			{Type: sbom.Edge_dependsOn, From: "a", To: []string{"b"}},
			{Type: sbom.Edge_dependsOn, From: "b", To: []string{"c"}},
			{Type: sbom.Edge_dependsOn, From: "c", To: []string{"d"}},
		},
		RootElements: []string{"a"},
	}

	keepDirectDependencies(nl)

	ids := make([]string, 0, len(nl.GetNodes()))
	for _, node := range nl.GetNodes() {
		ids = append(ids, node.GetId())
	}
	require.ElementsMatch(t, []string{"a", "b"}, ids)
}

// goModNode returns a Go module package node identified by its
// path and version, the way unpack's golang decomposer renders them.
func goModNode(path, version string) *sbom.Node {
	id := path + "@" + version
	return &sbom.Node{
		Id:      id,
		Type:    sbom.Node_PACKAGE,
		Name:    path,
		Version: version,
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): "pkg:golang/" + id,
		},
	}
}

// edgeTargets maps each edge source to its sorted targets.
func edgeTargets(nl *sbom.NodeList) map[string][]string {
	targets := map[string][]string{}
	for _, edge := range nl.GetEdges() {
		targets[edge.GetFrom()] = append(targets[edge.GetFrom()], edge.GetTo()...)
	}
	for from := range targets {
		slices.Sort(targets[from])
	}
	return targets
}

func nodeIDs(nl *sbom.NodeList) []string {
	ids := make([]string, 0, len(nl.GetNodes()))
	for _, node := range nl.GetNodes() {
		ids = append(ids, node.GetId())
	}
	return ids
}

func TestSelectGoModuleVersions(t *testing.T) {
	const (
		app       = "example.com/app@v1.0.0"
		oldApp    = "example.com/app@v0.1.0"
		libLow    = "example.com/lib@v1.2.0"
		libHigh   = "example.com/lib@v1.10.0"
		sysOld    = "golang.org/x/sys@v0.0.0-20201119102817-f84b799fce68"
		sysPseudo = "golang.org/x/sys@v0.0.0-20220715151400-c0bba94af5f8"
		sysTagged = "golang.org/x/sys@v0.1.0"
		incV1     = "example.com/inc@v1.5.0"
		incV2     = "example.com/inc@v2.0.0+incompatible"
		npmDep    = "leftpad"
	)
	node := func(id string) *sbom.Node {
		path, version, _ := strings.Cut(id, "@")
		return goModNode(path, version)
	}
	nl := &sbom.NodeList{
		Nodes: []*sbom.Node{
			node(app), node(oldApp), node(libLow), node(libHigh),
			node(sysOld), node(sysPseudo), node(sysTagged), node(incV1), node(incV2),
			{
				Id: npmDep, Type: sbom.Node_PACKAGE, Name: npmDep, Version: "1.0.0",
				Identifiers: map[int32]string{
					int32(sbom.SoftwareIdentifierType_PURL): "pkg:npm/leftpad@1.0.0",
				},
			},
		},
		Edges: []*sbom.Edge{
			{Type: sbom.Edge_dependsOn, From: app, To: []string{libLow, sysOld, incV1, npmDep}},
			// Two versions of one module that merge once rewired, an
			// older copy of the main module, and its own module path.
			{Type: sbom.Edge_dependsOn, From: libHigh, To: []string{sysTagged, sysOld, oldApp, incV2, libLow}},
			// Requirements of dropped versions go away with them.
			{Type: sbom.Edge_dependsOn, From: libLow, To: []string{sysPseudo}},
			{Type: sbom.Edge_dependsOn, From: sysOld, To: []string{npmDep}},
			{Type: sbom.Edge_dependsOn, From: oldApp, To: []string{npmDep}},
		},
		RootElements: []string{app},
	}

	selectGoModuleVersions(nl, goModuleVersions{})

	require.ElementsMatch(t, []string{app, libHigh, sysTagged, incV2, npmDep}, nodeIDs(nl),
		"each module path keeps its highest version, the main module keeps its own")
	require.Equal(t, map[string][]string{
		app:     {incV2, libHigh, sysTagged, npmDep},
		libHigh: {app, incV2, sysTagged},
	}, edgeTargets(nl))
	require.Equal(t, []string{app}, nl.GetRootElements())
}

// TestSelectGoModuleVersionsPruned pins that a main module with a
// pruned module graph selects what its go.mod requires, even over a
// higher version elsewhere in the graph, and drops modules it does
// not require.
func TestSelectGoModuleVersionsPruned(t *testing.T) {
	app := goModNode("example.com/app", "")
	stdlib := &sbom.Node{
		Id: "stdlib", Type: sbom.Node_PACKAGE, Name: "stdlib", Version: "1.26.0",
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): "pkg:golang/stdlib@1.26.0",
		},
	}
	lib := goModNode("example.com/lib", "v1.2.0")
	libOther := goModNode("example.com/lib", "v1.3.0")
	dep := goModNode("example.com/dep", "v0.5.0")
	testOnly := goModNode("example.com/testonly", "v0.1.0")
	nl := &sbom.NodeList{
		Nodes: []*sbom.Node{app, stdlib, lib, libOther, dep, testOnly},
		Edges: []*sbom.Edge{
			{Type: sbom.Edge_dependsOn, From: app.GetId(), To: []string{stdlib.GetId(), lib.GetId(), dep.GetId()}},
			{Type: sbom.Edge_dependsOn, From: dep.GetId(), To: []string{libOther.GetId(), testOnly.GetId()}},
		},
		RootElements: []string{app.GetId()},
	}

	selectGoModuleVersions(nl, goModuleVersions{pruned: true})

	require.ElementsMatch(t, []string{app.GetId(), stdlib.GetId(), lib.GetId(), dep.GetId()}, nodeIDs(nl))
	require.Equal(t, map[string][]string{
		app.GetId(): {dep.GetId(), lib.GetId(), stdlib.GetId()},
		dep.GetId(): {lib.GetId()},
	}, edgeTargets(nl))
}

// TestSelectGoModuleVersionsSum pins that without module graph
// pruning go.sum decides the version: its node wins over higher ones,
// and a node stands in for it when unpack created none.
func TestSelectGoModuleVersionsSum(t *testing.T) {
	app := goModNode("example.com/app", "")
	libRequired := goModNode("example.com/lib", "v1.2.0")
	libOther := goModNode("example.com/lib", "v1.1.0")
	depHigh := goModNode("example.com/dep", "v0.9.0")
	depSum := goModNode("example.com/dep", "v0.5.0")
	nl := &sbom.NodeList{
		Nodes: []*sbom.Node{app, libRequired, libOther, depHigh, depSum},
		Edges: []*sbom.Edge{
			{Type: sbom.Edge_dependsOn, From: app.GetId(), To: []string{libRequired.GetId(), depHigh.GetId()}},
			{Type: sbom.Edge_dependsOn, From: depSum.GetId(), To: []string{libOther.GetId()}},
			{Type: sbom.Edge_dependsOn, From: depHigh.GetId(), To: []string{depSum.GetId()}},
		},
		RootElements: []string{app.GetId()},
	}

	selectGoModuleVersions(nl, goModuleVersions{sum: map[string]string{
		"example.com/lib": "v1.4.0",
		"example.com/dep": "v0.5.0",
	}})

	require.ElementsMatch(t, []string{app.GetId(), libRequired.GetId(), depSum.GetId()}, nodeIDs(nl))
	require.Equal(t, "v1.4.0", libRequired.GetVersion())
	require.Equal(t, "pkg:golang/example.com/lib@v1.4.0", string(libRequired.Purl()))
	require.Equal(t, map[string][]string{
		app.GetId():    {depSum.GetId(), libRequired.GetId()},
		depSum.GetId(): {libRequired.GetId()},
	}, edgeTargets(nl))
}

// TestCodebaseGoVersionsDeterministic scans this repository's own
// module requirements, declared without module graph pruning, and pins
// that every run reports the versions go.sum selects. Which modules
// unpack reaches still varies with the go.mod files of the versions it
// picks, so only the versions are compared across runs.
func TestCodebaseGoVersionsDeterministic(t *testing.T) {
	goMod, err := os.ReadFile("../../go.mod")
	require.NoError(t, err)
	goSum, err := os.ReadFile("../../go.sum")
	require.NoError(t, err)
	file, err := modfile.Parse("go.mod", goMod, nil)
	require.NoError(t, err)
	require.NoError(t, file.AddGoStmt("1.16"))
	file.Toolchain = nil
	goMod, err = file.Format()
	require.NoError(t, err)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), goMod, 0o600)) //nolint:gosec // test temp dir
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.sum"), goSum, 0o600)) //nolint:gosec // test temp dir
	want := readGoModuleVersions(dir).sum
	require.NotEmpty(t, want)

	scan := func() map[string]string {
		nl, err := codebaseNodeList(context.Background(), dir, &Options{Offline: true})
		require.NoError(t, err)
		require.NotNil(t, nl)
		got := map[string]string{}
		for _, node := range nl.GetNodes() {
			if strings.HasPrefix(string(node.Purl()), "pkg:golang/") && node.GetName() != "stdlib" &&
				node.GetName() != file.Module.Mod.Path {
				require.NotContains(t, got, node.GetName(), "one version per module path")
				got[node.GetName()] = node.GetVersion()
			}
		}
		return got
	}
	for range 4 {
		for path, version := range scan() {
			require.Equal(t, want[path], version, "version of %s", path)
		}
	}
}

func TestReadGoModuleVersions(t *testing.T) {
	const goSum = `example.com/lib v1.2.0 h1:x=
example.com/lib v1.2.0/go.mod h1:x=
example.com/lib v1.10.0/go.mod h1:x=
example.com/lib v1.11.0/go.mod h1:x=
example.com/dep v0.0.0-20220715151400-c0bba94af5f8/go.mod h1:x=
example.com/dep v0.0.0-20201119102817-f84b799fce68/go.mod h1:x=
not a line
`
	for name, tc := range map[string]struct {
		goMod string
		sum   bool
		want  goModuleVersions
	}{
		"go 1.16": {
			goMod: "module example.com/app\n\ngo 1.16\n\nexclude example.com/lib v1.11.0\n",
			sum:   true,
			want: goModuleVersions{sum: map[string]string{
				"example.com/lib": "v1.10.0",
				"example.com/dep": "v0.0.0-20220715151400-c0bba94af5f8",
			}},
		},
		"no go.sum": {goMod: "module example.com/app\n\ngo 1.16\n", want: goModuleVersions{}},
		"go 1.17":   {goMod: "module example.com/app\n\ngo 1.17\n", sum: true, want: goModuleVersions{pruned: true}},
		"go 1.26.0": {goMod: "module example.com/app\n\ngo 1.26.0\n", want: goModuleVersions{pruned: true}},
		"no go directive": {
			goMod: "module example.com/app\n",
			sum:   true,
			want: goModuleVersions{sum: map[string]string{
				"example.com/lib": "v1.11.0",
				"example.com/dep": "v0.0.0-20220715151400-c0bba94af5f8",
			}},
		},
		"no go.mod": {want: goModuleVersions{}},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.goMod != "" {
				require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte(tc.goMod), 0o600))
			}
			if tc.sum {
				require.NoError(t, os.WriteFile(filepath.Join(dir, "go.sum"), []byte(goSum), 0o600))
			}
			require.Equal(t, tc.want, readGoModuleVersions(dir))
		})
	}
}

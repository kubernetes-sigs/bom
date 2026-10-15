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

package version

import (
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFromBuildInfo(t *testing.T) {
	t.Parallel()

	const fallback = "v0.22.0"

	for _, tc := range []struct {
		name string
		bi   *debug.BuildInfo
		want string
	}{
		{
			name: "no build information",
			want: fallback,
		},
		{
			name: "the bom command",
			bi: &debug.BuildInfo{
				Main: debug.Module{Path: modulePath, Version: "(devel)"},
			},
			want: fallback,
		},
		{
			name: "a binary that uses bom as a library",
			bi: &debug.BuildInfo{
				Main: debug.Module{Path: "k8s.io/release", Version: "v0.22.0"},
				Deps: []*debug.Module{
					{Path: "sigs.k8s.io/release-utils", Version: "v0.12.4"},
					{Path: modulePath, Version: "v0.8.0"},
				},
			},
			want: "v0.8.0",
		},
		{
			name: "a replaced bom dependency",
			bi: &debug.BuildInfo{
				Main: debug.Module{Path: "k8s.io/release"},
				Deps: []*debug.Module{{
					Path:    modulePath,
					Version: "v0.8.0",
					Replace: &debug.Module{Path: "github.com/example/bom", Version: "v0.8.1-fork"},
				}},
			},
			want: "v0.8.1-fork",
		},
		{
			name: "a local replacement",
			bi: &debug.BuildInfo{
				Main: debug.Module{Path: "k8s.io/release"},
				Deps: []*debug.Module{{
					Path:    modulePath,
					Version: "v0.8.0",
					Replace: &debug.Module{Path: "../bom", Version: "(devel)"},
				}},
			},
			want: devel,
		},
		{
			name: "a workspace module",
			bi: &debug.BuildInfo{
				Main: debug.Module{Path: "k8s.io/release"},
				Deps: []*debug.Module{{Path: modulePath, Version: "(devel)"}},
			},
			want: devel,
		},
		{
			name: "a binary without bom in its dependencies",
			bi: &debug.BuildInfo{
				Main: debug.Module{Path: "example.com/other"},
			},
			want: fallback,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, fromBuildInfo(tc.bi, fallback))
		})
	}
}

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

// Package version reports the version of bom that writes a document.
package version

import (
	"runtime/debug"
	"sync"

	releaseversion "sigs.k8s.io/release-utils/version"
)

const (
	// modulePath is the path of the bom module.
	modulePath = "sigs.k8s.io/bom"

	// devel is the version of a bom checkout built without version
	// information, like release-utils reports for the bom command.
	devel = "devel"
)

// Version returns the version of bom. The version of release-utils is the
// one of the binary, which is bom only for the bom command. Other binaries
// that use bom as a library, like krel, have it as a dependency in their
// build information.
var Version = sync.OnceValue(func() string {
	bi, _ := debug.ReadBuildInfo()

	return fromBuildInfo(bi, releaseversion.GetVersionInfo().GitVersion)
})

// fromBuildInfo returns the version of the bom dependency in the build
// information, or fallback when the binary is bom itself or doesn't list it.
// A local replacement or a workspace module has no version, which is devel.
func fromBuildInfo(bi *debug.BuildInfo, fallback string) string {
	if bi == nil || bi.Main.Path == modulePath {
		return fallback
	}

	for _, dep := range bi.Deps {
		if dep.Path != modulePath {
			continue
		}

		version := dep.Version
		if dep.Replace != nil {
			version = dep.Replace.Version
		}

		if version == "" || version == "(devel)" {
			return devel
		}

		return version
	}

	return fallback
}

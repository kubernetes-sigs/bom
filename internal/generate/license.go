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
	"path"
	"regexp"
	"strings"

	"github.com/protobom/protobom/pkg/sbom"
)

// spdxNone is the SPDX value asserting a file was scanned and no
// license was found in it, distinct from an empty value, which the
// serializers render as NOASSERTION.
const spdxNone = "NONE"

// licenseProcessorID names unpack's license scanner in its file
// processor registry. The scanner classifies every indexed file,
// recording the detected license on the node; concludeLicenses then
// settles the files it left untouched.
const licenseProcessorID = "license"

// licenseFilenameRe matches the file names the legacy license reader
// treated as license candidates when searching a tree.
var licenseFilenameRe = regexp.MustCompile(`(?i).*license.*`)

// concludeLicenses settles the license fields of an indexed file tree
// the way the legacy generator did: files with a license of their own
// keep it, and every other file concludes to the directory's own
// license while asserting NONE as its in-file license. Returns the
// directory license tag, empty when none was found.
func concludeLicenses(files *sbom.NodeList) string {
	tag := topLicenseTag(files)
	for _, node := range files.GetNodes() {
		if len(node.GetLicenses()) > 0 {
			continue
		}
		node.Licenses = []string{spdxNone}
		node.LicenseConcluded = tag
	}
	return tag
}

// topLicenseTag finds the license governing the directory among the
// classified file nodes, with the legacy reader's priorities: the
// first of the well-known root file names that exists wins, and
// failing that, the classified license-named file (Go sources
// excluded) closest to the root, shortest path breaking ties.
func topLicenseTag(files *sbom.NodeList) string {
	byName := map[string]*sbom.Node{}
	for _, node := range files.GetNodes() {
		byName[node.GetName()] = node
	}
	for _, name := range []string{"LICENSE", "LICENSE.txt", "COPYING", "COPYRIGHT"} {
		node, ok := byName[name]
		if !ok {
			continue
		}
		if lic := detectedLicense(node); lic != "" {
			return lic
		}
		// The legacy reader classified only the first candidate
		// present, searching the tree when it held no recognizable
		// license.
		break
	}

	best := ""
	bestDepth := 0
	bestLen := 0
	for _, node := range files.GetNodes() {
		lic := detectedLicense(node)
		if lic == "" {
			continue
		}
		name := node.GetName()
		if path.Ext(name) == ".go" || !licenseFilenameRe.MatchString(path.Base(name)) {
			continue
		}
		depth := strings.Count(name, "/")
		if best == "" || depth < bestDepth || (depth == bestDepth && len(name) < bestLen) {
			best = lic
			bestDepth = depth
			bestLen = len(name)
		}
	}
	return best
}

// detectedLicense returns the license the scanner classified for a
// file node, empty when the file matched none.
func detectedLicense(node *sbom.Node) string {
	if lics := node.GetLicenses(); len(lics) > 0 && lics[0] != spdxNone {
		return lics[0]
	}
	return ""
}

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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/sirupsen/logrus"
)

// assumedSPDXVersion is the version a document declaring none is read
// as. SPDX 2.3 is the most permissive of the 2.x schemas.
const assumedSPDXVersion = "SPDX-2.3"

// sanitize repairs the violations of the SPDX specification that
// bom's hand-written parser, up to v0.7.1, read through and that
// real-world documents carry, and describes each repair. protobom
// validates what it parses and rejects them. In SPDX JSON documents:
//
//   - a missing or empty spdxVersion, which keeps the document from
//     being recognized as SPDX at all: it is read as SPDX 2.3;
//   - element identifiers without the SPDXRef- prefix: it is added;
//   - a package originator or supplier that is not NOASSERTION nor an
//     SPDX actor ("Person: ..." or "Organization: ..."): an empty one
//     is dropped, any other is taken as the name of a person, which is
//     what the free-form values seen in the wild hold.
//
// In SPDX tag-value documents, element identifiers without the
// SPDXRef- prefix are repaired.
//
// Documents that are not SPDX, or need none of those repairs, come
// back without any.
func sanitize(data []byte) (fixed []byte, fixes []string) {
	if fixed, fixes := sanitizeJSON(data); len(fixes) > 0 {
		return fixed, fixes
	}
	return sanitizeTagValue(data)
}

func sanitizeJSON(data []byte) (fixed []byte, fixes []string) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, nil
	}
	// Anything after the document is not repaired away: the strict
	// error stands.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, nil
	}
	if str(doc["SPDXID"]) != "SPDXRef-DOCUMENT" {
		return nil, nil
	}

	if str(doc["spdxVersion"]) == "" {
		doc["spdxVersion"] = assumedSPDXVersion
		fixes = append(fixes, "document declares no spdxVersion, reading it as "+assumedSPDXVersion)
	}

	dropped, persons := 0, 0
	for _, pkg := range objects(doc["packages"]) {
		for _, field := range []string{"originator", "supplier"} {
			raw, ok := pkg[field]
			if !ok {
				continue
			}
			value := str(raw)
			switch {
			case value == "NOASSERTION" || strings.Contains(value, ":"):
			case strings.TrimSpace(value) == "":
				delete(pkg, field)
				dropped++
			default:
				pkg[field] = "Person: " + value
				persons++
			}
		}
	}
	if dropped > 0 {
		fixes = append(fixes, fmt.Sprintf("dropping %d empty package originators or suppliers", dropped))
	}
	if persons > 0 {
		fixes = append(fixes, fmt.Sprintf("reading %d package originators or suppliers without an actor type as persons", persons))
	}
	if n := prefixElementIDs(doc); n > 0 {
		fixes = append(fixes, prefixFix(n))
	}
	if len(fixes) == 0 {
		return nil, nil
	}

	// tools-golang, which protobom parses SPDX with, reads actors
	// without decoding JSON escapes, so none must be introduced.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, nil
	}
	return buf.Bytes(), fixes
}

const idPrefix = "SPDXRef-"

func prefixFix(n int) string {
	return fmt.Sprintf("prefixing %d element identifiers with %s", n, idPrefix)
}

// toRename returns the identifiers among ids that lack the SPDXRef-
// prefix and can take it: one whose prefixed form the document
// defines as well is left alone, with a warning, since renaming it
// would merge two elements.
func toRename(ids []string) map[string]bool {
	defined := map[string]bool{}
	for _, id := range ids {
		defined[id] = true
	}
	renamed := map[string]bool{}
	for _, id := range ids {
		if id == "" || strings.HasPrefix(id, idPrefix) || renamed[id] {
			continue
		}
		if defined[idPrefix+id] {
			logrus.Warnf("SBOM defines both %s and %s%s, not prefixing the former", id, idPrefix, id)
			continue
		}
		renamed[id] = true
	}
	return renamed
}

// prefixElementIDs adds the SPDXRef- prefix to the identifiers of the
// document's elements that lack it, and to every reference to them.
// It returns the number of elements renamed.
func prefixElementIDs(doc map[string]any) int {
	var ids []string
	for _, key := range []string{"packages", "files", "snippets"} {
		for _, element := range objects(doc[key]) {
			ids = append(ids, str(element["SPDXID"]))
		}
	}
	renamed := toRename(ids)
	if len(renamed) == 0 {
		return 0
	}

	rename := func(obj map[string]any, field string) {
		switch v := obj[field].(type) {
		case string:
			if renamed[v] {
				obj[field] = idPrefix + v
			}
		case []any:
			for i, id := range v {
				if s := str(id); renamed[s] {
					v[i] = idPrefix + s
				}
			}
		}
	}
	for _, key := range []string{"packages", "files", "snippets"} {
		for _, element := range objects(doc[key]) {
			rename(element, "SPDXID")
		}
	}
	rename(doc, "documentDescribes")
	for _, ref := range []struct{ list, field string }{
		{"relationships", "spdxElementId"},
		{"relationships", "relatedSpdxElement"},
		{"packages", "hasFiles"},
		{"snippets", "snippetFromFile"},
	} {
		for _, obj := range objects(doc[ref.list]) {
			rename(obj, ref.field)
		}
	}
	for _, snippet := range objects(doc["snippets"]) {
		for _, r := range objects(snippet["ranges"]) {
			for _, pointer := range []string{"startPointer", "endPointer"} {
				if obj, ok := r[pointer].(map[string]any); ok {
					rename(obj, "reference")
				}
			}
		}
	}
	return len(renamed)
}

// tagValueLine is a line of a tag-value document. Tag is empty for
// lines that hold no tag: blank ones, comments and the continuation
// of multi-line <text> values.
type tagValueLine struct {
	raw, tag, value, eol string
}

func splitTagValue(data []byte) []tagValueLine {
	var lines []tagValueLine
	inText := false
	for _, raw := range strings.SplitAfter(string(data), "\n") {
		if raw == "" {
			continue
		}
		body := strings.TrimRight(raw, "\r\n")
		line := tagValueLine{raw: raw, eol: raw[len(body):]}
		if inText {
			inText = !strings.Contains(body, "</text>")
			lines = append(lines, line)
			continue
		}
		tag, value, ok := strings.Cut(body, ":")
		if ok && !strings.HasPrefix(strings.TrimSpace(tag), "#") {
			line.tag = strings.TrimSpace(tag)
			line.value = strings.TrimSpace(value)
			if strings.HasPrefix(line.value, "<text>") && !strings.Contains(line.value, "</text>") {
				inText = true
			}
		}
		lines = append(lines, line)
	}
	return lines
}

// sanitizeTagValue adds the SPDXRef- prefix to the element identifiers
// of a tag-value document that lack it, and to every reference to
// them.
func sanitizeTagValue(data []byte) (fixed []byte, fixes []string) {
	lines := splitTagValue(data)
	isSPDX := false
	var ids []string
	for _, line := range lines {
		switch line.tag {
		case "SPDXVersion":
			isSPDX = true
		case "SPDXID":
			ids = append(ids, line.value)
		}
	}
	if !isSPDX {
		return nil, nil
	}
	renamed := toRename(ids)
	if len(renamed) == 0 {
		return nil, nil
	}

	prefixed := func(id string) string {
		if renamed[id] {
			return idPrefix + id
		}
		return id
	}
	var buf bytes.Buffer
	for _, line := range lines {
		value := line.value
		switch line.tag {
		case "SPDXID", "SnippetFromFileSPDXID", "SPDXREF":
			value = prefixed(value)
		case "Relationship":
			if fields := strings.Fields(value); len(fields) == 3 {
				value = strings.Join([]string{prefixed(fields[0]), fields[1], prefixed(fields[2])}, " ")
			}
		}
		if value == line.value {
			buf.WriteString(line.raw)
			continue
		}
		buf.WriteString(line.tag + ": " + value + line.eol)
	}
	return buf.Bytes(), []string{prefixFix(len(renamed))}
}

// str returns v if it is a string, an empty string otherwise.
func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// objects returns the JSON objects in v if it is an array.
func objects(v any) []map[string]any {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	var objs []map[string]any
	for _, item := range list {
		if obj, ok := item.(map[string]any); ok {
			objs = append(objs, obj)
		}
	}
	return objs
}

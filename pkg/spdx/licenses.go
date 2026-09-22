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

package spdx

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	unpacklicense "github.com/carabiner-dev/unpack/license"
	"github.com/github/go-spdx/v2/spdxexp"
)

// licenseRefPrefix starts the identifiers of licenses not on the SPDX
// license list.
const licenseRefPrefix = "LicenseRef-"

// SPDX license expression operators.
const (
	licenseAnd = "AND"
	licenseOr  = "OR"
)

// ExtractedLicense is a license not on the SPDX license list, referenced
// from license expressions of the document by its LicenseRef- identifier.
type ExtractedLicense struct {
	ID   string // LicenseRef-public-domain
	Name string // public-domain
	Text string // The text of the license, or a note on where it came from
}

// licenseRefs collects the LicenseRef- identifiers minted while
// normalizing the license data of a document, so the document can carry
// the extracted licensing information SPDX requires for each of them.
//
// Identifiers are assigned in two passes so that they do not depend on
// the order the names are met: while collecting, the names needing an
// identifier are only recorded; assign then hands out the identifiers
// in the order of the sorted names.
//
// A verbatim licenseRefs leaves the license data as it is and mints
// nothing: documents read from SPDX already carry valid expressions and
// define their own extracted licensing information.
type licenseRefs struct {
	verbatim   bool
	collecting bool
	pending    map[string]struct{} // license names met while collecting
	byName     map[string]string   // license name -> LicenseRef- identifier
	byID       map[string]string   // LicenseRef- identifier -> license name
}

func newLicenseRefs() *licenseRefs {
	return &licenseRefs{
		pending: map[string]struct{}{},
		byName:  map[string]string{},
		byID:    map[string]string{},
	}
}

// declaredLicenseOperator returns the operator joining the list of
// licenses a package declares, chosen by the ecosystem of its purl
// type, as the ecosystems define such lists:
//
//	deb       AND  debian/copyright: each Files stanza licenses part of the package
//	rpm, apk  AND  a single License field; lists never occur, all would apply
//	alpm      AND  PKGBUILD license array: every license listed applies
//	composer  OR   composer.json: a license array is a disjunction (dual licensing)
//	maven     OR   POM reference: with several licenses the user can pick any
//	npm       OR   the legacy licenses array was used for dual licensing
//	gem       OR   gemspec licenses: commonly dual licenses (MIT, Ruby)
//	pypi      OR   trove classifiers do not say; the pre-existing behavior
//	other     OR   cargo and golang declare single expressions, and the rest
//	               is unknown: the pre-existing behavior
func declaredLicenseOperator(purl string) string {
	typ, _, _ := strings.Cut(strings.TrimPrefix(purl, "pkg:"), "/")
	switch strings.ToLower(typ) {
	case "deb", "rpm", "apk", "alpm":
		return licenseAnd
	default:
		return licenseOr
	}
}

// licenseOperatorRe matches the conjunctions of a license expression,
// spelled in either case: package managers (Debian's DEP-5 among them)
// write them lowercase.
var licenseOperatorRe = regexp.MustCompile(`\s+(?i:(and|or))\s+`)

// licenseTokenRe matches a license short name written as a single token
// that looks like an identifier (it carries a capital letter, a digit
// or punctuation), like the GPL-2+ or Expat of Debian's copyright
// files, as opposed to a plain English word like "later".
var licenseTokenRe = regexp.MustCompile(`^[A-Za-z0-9.+-]*[A-Z0-9.+-][A-Za-z0-9.+-]*$`)

// licenseRefPlaceholder stands in for the identifiers not assigned
// yet while collecting.
const licenseRefPlaceholder = licenseRefPrefix + "bom-placeholder"

// dashesRe matches runs of dashes.
var dashesRe = regexp.MustCompile(`-{2,}`)

// idstringInvalidRe matches runs of characters not allowed in the
// idstring of a LicenseRef- identifier.
var idstringInvalidRe = regexp.MustCompile(`[^A-Za-z0-9.-]+`)

// ambiguousLicenseNames are names unpack's alias data (the CycloneDX
// mapping) resolves to one specific license although they name a whole
// family: BSD to BSD-4-Clause and Apache License to Apache-1.0, for
// example. They become LicenseRef- identifiers instead. Decomposers
// normalize the names they read themselves, so this only catches names
// reaching bom verbatim.
var ambiguousLicenseNames = map[string]struct{}{
	"apache license":           {},
	"apache software licenses": {},
	"bsd":                      {},
	"bsd license":              {},
	"the bsd license":          {},
	"mozilla public license":   {},
}

// expression normalizes a list of license names or expressions, as
// package managers declare them, into a single valid SPDX license
// expression joining them with the operator. Each entry is mapped to
// SPDX identifiers where they are known, and entries (or components of
// them) that cannot be are replaced by LicenseRef- identifiers.
// Returns an empty string when there is nothing to declare.
func (r *licenseRefs) expression(names []string, operator string) string {
	terms := []string{}
	for _, name := range names {
		term := r.normalize(name)
		if term == "" || slices.Contains(terms, term) {
			continue
		}
		terms = append(terms, term)
	}
	return joinLicenses(terms, operator)
}

// joinLicenses joins license expressions with the operator,
// parenthesizing the compound ones so they keep their meaning. A list
// asserting nothing about one of its entries asserts nothing as a
// whole.
func joinLicenses(terms []string, operator string) string {
	if len(terms) == 1 {
		return terms[0]
	}
	parts := make([]string, 0, len(terms))
	for _, term := range terms {
		switch {
		case term == NOASSERTION || term == NONE:
			return NOASSERTION
		case licenseOperatorRe.MatchString(term):
			parts = append(parts, "("+term+")")
		default:
			parts = append(parts, term)
		}
	}
	return strings.Join(parts, " "+operator+" ")
}

// normalize turns a license name or expression into a valid SPDX
// license expression. NONE and NOASSERTION pass through; a compound
// expression containing either of them says nothing certain about the
// licensing, so it becomes NOASSERTION as a whole.
func (r *licenseRefs) normalize(name string) string {
	name = strings.TrimSpace(name)
	switch name {
	case "":
		return ""
	case NONE, NOASSERTION:
		return name
	}
	if r.verbatim {
		return name
	}
	if expr, ok := validExpression(name); ok {
		// Identifiers the input carried already need extracted
		// licensing information as much as the minted ones.
		r.adopt(expr)
		return expr
	}

	// Compound entries are normalized component by component, so a
	// single unknown name does not hide the known licenses next to
	// it. That is only safe when every component is a license on its
	// own: free text like "GPL v2 or later" merely reads like an
	// expression. Parentheses would need a real parser: such entries
	// are kept whole.
	if strings.ContainsAny(name, "()") || !licenseOperatorRe.MatchString(name) {
		return r.ref(name)
	}
	components := licenseOperatorRe.Split(name, -1)
	operators := licenseOperatorRe.FindAllStringSubmatch(name, -1)
	terms := make([]string, len(components))
	for i, component := range components {
		switch normalized, ok := validExpression(component); {
		case component == NONE || component == NOASSERTION:
			return NOASSERTION
		case ok:
			terms[i] = normalized
		case licenseTokenRe.MatchString(component):
			terms[i] = ""
		default:
			return r.ref(name)
		}
	}
	var expr strings.Builder
	for i, component := range components {
		if i > 0 {
			expr.WriteString(" " + strings.ToUpper(operators[i-1][1]) + " ")
		}
		if terms[i] == "" {
			terms[i] = r.ref(component)
		}
		expr.WriteString(terms[i])
	}
	if normalized, ok := validExpression(expr.String()); ok {
		r.adopt(normalized)
		return normalized
	}
	return r.ref(name)
}

// licenseRefRe matches the LicenseRef- identifiers of an expression,
// along with the DocumentRef- prefix of those defined in another
// document.
var licenseRefRe = regexp.MustCompile(`(DocumentRef-[A-Za-z0-9.-]+:)?` + licenseRefPrefix + `[A-Za-z0-9.-]+`)

// adopt records the LicenseRef- identifiers of a valid expression that
// were not minted here. Identifiers referencing another document are
// defined there, not in this document.
func (r *licenseRefs) adopt(expr string) {
	for _, match := range licenseRefRe.FindAllStringSubmatch(expr, -1) {
		if match[1] != "" || (r.collecting && match[0] == licenseRefPlaceholder) {
			continue
		}
		if _, ok := r.byID[match[0]]; !ok {
			r.byID[match[0]] = strings.TrimPrefix(match[0], licenseRefPrefix)
		}
	}
}

// validExpression maps a license name to its SPDX identifier when it
// has one and reports whether the result is a valid SPDX license
// expression, returning it with the identifiers in their canonical
// case.
//
// Identifiers are validated against the license list go-spdx embeds,
// which is usually newer than the version the document declares
// (license.DefaultCatalogOpts). bom's own catalog is downloaded on
// demand rather than embedded, and requiring it here would put network
// access in the way of every conversion; an identifier added to the
// list after the declared version is the (rare) price.
func validExpression(name string) (string, bool) {
	name = strings.TrimSpace(name)
	if _, ok := ambiguousLicenseNames[strings.ToLower(name)]; ok {
		return "", false
	}
	name = unpacklicense.Normalize(name, "")
	normalized, invalid := spdxexp.ValidateAndNormalizeLicensesWithOptions(
		[]string{name}, spdxexp.ValidateLicensesOptions{},
	)
	if len(invalid) > 0 || len(normalized) != 1 {
		return "", false
	}
	return normalized[0], true
}

// ref returns the LicenseRef- identifier of a license name. While
// collecting, the name is recorded and a placeholder returned; names
// only met after assign get their identifier right away.
func (r *licenseRefs) ref(name string) string {
	name = strings.TrimSpace(name)
	if id, ok := r.byName[name]; ok {
		return id
	}
	if r.collecting {
		r.pending[name] = struct{}{}
		return licenseRefPlaceholder
	}
	return r.mint(name)
}

// assign ends the collection, minting the identifiers of the names met
// in the order of the sorted names.
func (r *licenseRefs) assign() {
	r.collecting = false
	for _, name := range slices.Sorted(maps.Keys(r.pending)) {
		r.ref(name)
	}
	r.pending = map[string]struct{}{}
}

// mint returns a new LicenseRef- identifier for a license name. A plus
// sign reads "or later", an existing LicenseRef- prefix is not
// repeated, and names sanitizing to the same identifier get a -dupN
// suffix, which cannot be mistaken for a version.
func (r *licenseRefs) mint(name string) string {
	idstring := strings.TrimPrefix(name, licenseRefPrefix)
	idstring = strings.ReplaceAll(idstring, "+", "-or-later-")
	idstring = strings.Trim(idstringInvalidRe.ReplaceAllString(idstring, "-"), "-")
	idstring = dashesRe.ReplaceAllString(idstring, "-")
	if idstring == "" {
		idstring = "unknown"
	}
	id := licenseRefPrefix + idstring
	for i := 1; ; i++ {
		if _, taken := r.byID[id]; !taken {
			break
		}
		id = fmt.Sprintf("%s%s-dup%d", licenseRefPrefix, idstring, i)
	}
	r.byName[name] = id
	r.byID[id] = name
	return id
}

// extracted returns the extracted licensing information of every
// minted identifier, sorted by identifier.
func (r *licenseRefs) extracted() []ExtractedLicense {
	if r.verbatim || len(r.byID) == 0 {
		return nil
	}
	ret := make([]ExtractedLicense, 0, len(r.byID))
	for _, id := range slices.Sorted(maps.Keys(r.byID)) {
		ret = append(ret, ExtractedLicense{
			ID:   id,
			Name: r.byID[id],
			Text: NOASSERTION,
		})
	}
	return ret
}

// licenseList splits a license expression into the individual licenses
// it references, sorted, as the SPDX fields listing licenses found in
// files require. NONE and NOASSERTION stand alone, an empty expression
// asserts nothing, and an expression that does not parse is kept whole.
func licenseList(expr string) []string {
	expr = strings.TrimSpace(expr)
	switch expr {
	case "":
		return []string{NOASSERTION}
	case NONE, NOASSERTION:
		return []string{expr}
	}
	ids, err := spdxexp.ExtractLicenses(expr)
	if err != nil || len(ids) == 0 {
		return []string{expr}
	}
	slices.Sort(ids)
	return ids
}

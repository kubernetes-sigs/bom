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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLicenseRefsNormalize(t *testing.T) {
	for name, tc := range map[string]struct {
		input    string
		expected string
	}{
		"empty":                   {"", ""},
		"spdx id":                 {"Apache-2.0", "Apache-2.0"},
		"id in another case":      {"bsd-4-clause-uc", "BSD-4-Clause-UC"},
		"license name":            {"MIT License", "MIT"},
		"expression":              {"MIT OR Apache-2.0", "MIT OR Apache-2.0"},
		"lowercase operators":     {"GPL-2.0-only or MIT", "GPL-2.0-only OR MIT"},
		"lowercase or":            {"MIT or Apache-2.0", "MIT OR Apache-2.0"},
		"known exception":         {"GPL-2.0-or-later WITH Classpath-exception-2.0", "GPL-2.0-or-later WITH Classpath-exception-2.0"},
		"none":                    {NONE, NONE},
		"noassertion":             {NOASSERTION, NOASSERTION},
		"noassertion in compound": {"NOASSERTION OR MIT", NOASSERTION},
		"unknown":                 {"public-domain", "LicenseRef-public-domain"},
		"unknown exception":       {"GPL-3+ with Autoconf-data exception", "LicenseRef-GPL-3-or-later-with-Autoconf-data-exception"},
		"partly known":            {"Artistic-1.0-Perl or GPL-1+", "Artistic-1.0-Perl OR LicenseRef-GPL-1-or-later"},
		"free text or later":      {"GPL v2 or later", "LicenseRef-GPL-v2-or-later"},
		"free text any later":     {"GPLv2 or any later version", "LicenseRef-GPLv2-or-any-later-version"},
		"free text and":           {"Copyright and permission notice", "LicenseRef-Copyright-and-permission-notice"},
		"parenthesized":           {"(MIT OR custom) AND Zlib", "LicenseRef-MIT-OR-custom-AND-Zlib"},
		"existing licenseref":     {"LicenseRef-mine", "LicenseRef-mine"},
		"invalid licenseref":      {"LicenseRef-foo_bar", "LicenseRef-foo-bar"},
		"other document":          {"DocumentRef-spdx-tool-1.2:LicenseRef-mine", "DocumentRef-spdx-tool-1.2:LicenseRef-mine"},
		"plus":                    {"GPLv2+", "LicenseRef-GPLv2-or-later"},
		"ambiguous bsd":           {"BSD", "LicenseRef-BSD"},
		"ambiguous apache":        {"Apache License", "LicenseRef-Apache-License"},
		"nothing but symbols":     {"???", "LicenseRef-unknown"},
		"surrounding spaces":      {"  MIT  ", "MIT"},
		"unknown with version":    {"GFDL-NIV-1.3", "LicenseRef-GFDL-NIV-1.3"},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.expected, newLicenseRefs().normalize(tc.input))
		})
	}
}

func TestLicenseRefsVerbatim(t *testing.T) {
	refs := &licenseRefs{verbatim: true}
	require.Equal(t, "GPL v2 or later", refs.normalize(" GPL v2 or later "))
	require.Equal(t, "LicenseRef-x AND MIT", refs.expression([]string{"LicenseRef-x", "MIT"}, licenseAnd))
	require.Nil(t, refs.extracted())
}

func TestLicenseRefsExpression(t *testing.T) {
	refs := newLicenseRefs()
	require.Empty(t, refs.expression(nil, licenseAnd))
	require.Equal(t, "MIT", refs.expression([]string{"MIT", "MIT"}, licenseAnd))
	require.Equal(t,
		"GPL-2.0-or-later AND (MIT OR Apache-2.0) AND LicenseRef-public-domain",
		refs.expression([]string{"GPL-2.0-or-later", "MIT OR Apache-2.0", "public-domain"}, licenseAnd),
	)
	require.Equal(t,
		"LGPL-2.1-only OR GPL-3.0-or-later",
		refs.expression([]string{"LGPL-2.1-only", "GPL-3.0-or-later"}, licenseOr),
	)
	require.Equal(t, NOASSERTION, refs.expression([]string{"MIT", NOASSERTION}, licenseOr))
	_, ok := validExpression(refs.expression([]string{"public-domain", "custom", "GPL-3+ with Bison exception", "ISC"}, licenseAnd))
	require.True(t, ok, "the joined expression must be valid")
}

func TestDeclaredLicenseOperator(t *testing.T) {
	for purl, expected := range map[string]string{
		"pkg:deb/debian/coreutils@9.1-1":     licenseAnd,
		"pkg:rpm/fedora/bash@5.2":            licenseAnd,
		"pkg:apk/alpine/musl@1.2.4":          licenseAnd,
		"pkg:composer/monolog/monolog@3.0.0": licenseOr,
		"pkg:maven/org.example/lib@1.0":      licenseOr,
		"pkg:npm/left-pad@1.3.0":             licenseOr,
		"pkg:golang/sigs.k8s.io/bom@v0.7.1":  licenseOr,
		"":                                   licenseOr,
	} {
		require.Equal(t, expected, declaredLicenseOperator(purl), purl)
	}
}

func TestLicenseRefsExtracted(t *testing.T) {
	refs := newLicenseRefs()
	require.Nil(t, refs.extracted())

	// Names sanitizing to the same idstring get suffixed identifiers
	// that do not read like versions.
	require.Equal(t, "LicenseRef-public-domain", refs.normalize("public-domain"))
	require.Equal(t, "LicenseRef-public-domain-dup1", refs.normalize("public domain"))
	require.Equal(t, "LicenseRef-public-domain", refs.normalize("public-domain"), "names map to one identifier")
	require.Equal(t, "LicenseRef-mine", refs.normalize("LicenseRef-mine"))
	require.Equal(t, "Apache-2.0 OR DocumentRef-other:LicenseRef-theirs", refs.normalize("Apache-2.0 OR DocumentRef-other:LicenseRef-theirs"))

	extracted := refs.extracted()
	require.Len(t, extracted, 3, "identifiers of other documents are not extracted here")
	require.Equal(t, "LicenseRef-mine", extracted[0].ID, "sorted by identifier")
	require.Equal(t, "mine", extracted[0].Name)
	require.Equal(t, "LicenseRef-public-domain", extracted[1].ID)
	require.Equal(t, "public-domain", extracted[1].Name)
	require.Equal(t, "LicenseRef-public-domain-dup1", extracted[2].ID)
	require.Equal(t, "public domain", extracted[2].Name)
	for _, lic := range extracted {
		require.NotEmpty(t, lic.Text, "SPDX requires an extracted text")
	}
}

// TestLicenseRefsOrderIndependent checks that collected names get the
// same identifiers whatever the order they are met in.
func TestLicenseRefsOrderIndependent(t *testing.T) {
	names := []string{"GPL", "GPL+", "GPL ", "G.P.L", "LicenseRef-GPL-or-later"}
	var first map[string]string
	for _, order := range [][]int{{0, 1, 2, 3, 4}, {4, 3, 2, 1, 0}, {2, 0, 4, 1, 3}} {
		refs := newLicenseRefs()
		refs.collecting = true
		for _, i := range order {
			refs.normalize(names[i])
		}
		refs.assign()
		got := map[string]string{}
		for _, name := range names {
			got[name] = refs.normalize(name)
		}
		if first == nil {
			first = got
			continue
		}
		require.Equal(t, first, got)
	}
	require.Equal(t, "LicenseRef-GPL", first["GPL"])
	require.Equal(t, "LicenseRef-GPL-or-later", first["LicenseRef-GPL-or-later"], "adopted identifiers are kept")
	require.Equal(t, "LicenseRef-GPL-or-later-dup1", first["GPL+"])
}

func TestLicenseList(t *testing.T) {
	for input, expected := range map[string][]string{
		"":                                     {NOASSERTION},
		NONE:                                   {NONE},
		"MIT":                                  {"MIT"},
		"(MIT AND BSD-3-Clause) OR Apache-2.0": {"Apache-2.0", "BSD-3-Clause", "MIT"},
		"(MIT OR Apache-2.0) AND LicenseRef-custom": {"Apache-2.0", "LicenseRef-custom", "MIT"},
		"not an expression (":                       {"not an expression ("},
	} {
		require.Equal(t, expected, licenseList(input), input)
	}
}

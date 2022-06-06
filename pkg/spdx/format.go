/*
Copyright 2022 The Kubernetes Authors.

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
	"bytes"
	"strings"

	// TODO: These should be removed once version v0.4.0 is released
	// in https://github.com/spdx/tools-golang.
	//
	// This fork is required to prevent error "got unknown checksum type SHA512".
	//
	// See also:
	// - https://github.com/kubernetes-sigs/bom/pull/104
	// - https://github.com/spdx/tools-golang/pull/139
	// - https://github.com/spdx/tools-golang/issues/96
	spdxjson "github.com/this-is-a-fork-remove-me-asap/tools-golang/json"
	spdxtv "github.com/this-is-a-fork-remove-me-asap/tools-golang/tvloader"
)

// Format is valid format for an SPDX document.
type Format string

// FormatTagValue is the default format for an SPDX document.
const FormatTagValue = "tv"

// FormatJSON is the JSON format for an SPDX document.
const FormatJSON = "json"

func ConvertTagValueToJSON(rawTagValueDocument string) (string, error) {
	doc, err := spdxtv.Load2_2(strings.NewReader(rawTagValueDocument))
	if err != nil {
		return "", err
	}
	buf := new(bytes.Buffer)
	if err := spdxjson.Save2_2(doc, buf); err != nil {
		return "", err
	}
	return buf.String(), nil
}

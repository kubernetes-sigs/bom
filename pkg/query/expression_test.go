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

package query

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTokenizeExpression(t *testing.T) {
	tokens := tokenizeExpression("Hello Friend")
	require.Len(t, tokens, 2)
	tokens = tokenizeExpression("\"Hello Friend\"")
	require.Len(t, tokens, 1)
	tokens = tokenizeExpression(`depth:1 name:"Hola Mano"`)
	require.Len(t, tokens, 2)
}

func TestParseExpression(t *testing.T) {
	exp, err := parseExpression(`depth:1 name:"Hola Mano"`)
	require.NoError(t, err)
	require.Len(t, exp.Filters, 2)
	_, ok := exp.Filters[0].(*DepthFilter)
	require.True(t, ok)
	_, ok2 := exp.Filters[1].(*NameFilter)
	require.True(t, ok2)
	require.Equal(t, "Hola Mano", exp.Filters[1].(*NameFilter).Pattern)
}

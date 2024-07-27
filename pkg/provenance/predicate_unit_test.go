/*
Copyright 2021 The Kubernetes Authors.

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

package provenance

import (
	"os"
	"testing"

	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	"github.com/stretchr/testify/require"
)

func TestWrite(t *testing.T) {
	p := NewSLSAPredicate()
	tmp, err := os.CreateTemp("", "predicate-test")
	require.NoError(t, err)
	defer os.Remove(tmp.Name())

	res := p.Write(tmp.Name())
	require.NoError(t, res)
	require.FileExists(t, tmp.Name())
	s, err := os.Stat(tmp.Name())
	require.NoError(t, err)
	require.Positive(t, s.Size())
}

func TestAddMaterial(t *testing.T) {
	p := NewSLSAPredicate()
	sha1 := "c91cc89922941ace4f79113227a0166f24b8a98b"
	p.AddMaterial("https://www.example.com/", common.DigestSet{"sha1": sha1})
	require.Len(t, p.Materials, 1)
	require.Equal(t, sha1, p.Materials[0].Digest["sha1"])
}

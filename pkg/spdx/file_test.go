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

package spdx

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func createTempFile(name string) (*os.File, string, error) {
	dir, err := ioutil.TempDir("", "tests")
	if err != nil {
		return nil, "", err
	}
	file, err := ioutil.TempFile(dir, name)
	if err != nil {
		return nil, "", err
	}

	return file, dir, err
}

func TestGetFileType(t *testing.T) {
	file, dir, err := createTempFile("temp.*.bat")
	require.NoError(t, err)

	fileType := getFileTypes(file.Name())

	require.Len(t, fileType, 2)
	require.EqualValues(t, []string{"BINARY", "APPLICATION"}, fileType)
	require.NoError(t, os.RemoveAll(dir))

	file, dir, err = createTempFile("honk.*.go")
	require.NoError(t, err)

	fileType = getFileTypes(file.Name())

	require.Len(t, fileType, 1)
	require.EqualValues(t, []string{"SOURCE"}, fileType)
	require.NoError(t, os.RemoveAll(dir))

	file, dir, err = createTempFile("honk.*.mp3")
	require.NoError(t, err)

	fileType = getFileTypes(file.Name())

	require.Len(t, fileType, 1)
	require.EqualValues(t, []string{"AUDIO"}, fileType)
	require.NoError(t, os.RemoveAll(dir))

	file, dir, err = createTempFile("say.*.honk")
	require.NoError(t, err)

	fileType = getFileTypes(file.Name())

	require.Len(t, fileType, 1)
	require.EqualValues(t, []string{"OTHER"}, fileType)
	require.NoError(t, os.RemoveAll(dir))
}

/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
 * https://www.fibratus.io
 * All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package functions

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestSymlink(t *testing.T) {
	ln, err := createSymlink()
	require.NoError(t, err)
	call := Symlink{}
	res, _ := call.Call([]interface{}{ln})
	defer func() {
		_ = os.RemoveAll(filepath.Join(os.TempDir(), "test"))
	}()
	assert.Equal(t, filepath.Join(os.TempDir(), "test", "target.txt"), res)
}

func createSymlink() (string, error) {
	path := filepath.Join(os.TempDir(), "test")
	target := "target.txt"
	if err := os.MkdirAll(path, 0755); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(path, "target.txt"), []byte("Test\n"), os.ModePerm); err != nil {
		return "", err
	}
	symlink := filepath.Join(path, "symlink.txt")
	return symlink, os.Symlink(target, symlink)
}

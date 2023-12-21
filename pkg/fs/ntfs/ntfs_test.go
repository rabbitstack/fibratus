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

package ntfs

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestRead(t *testing.T) {
	file := filepath.Join(os.TempDir(), "ntfs-read.txt")
	err := os.WriteFile(file, []byte("ntfs read"), os.ModePerm)
	require.NoError(t, err)
	defer os.Remove(file)

	stat, err := os.Stat(file)
	require.NoError(t, err)

	fs := NewFS()
	defer fs.Close()

	b, n, err := fs.Read(file, 0, stat.Size())
	assert.NotNil(t, fs)
	require.NoError(t, err)
	require.True(t, n != 0)

	assert.Equal(t, []byte("ntfs read"), b)

	f, err := os.OpenFile(file, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	require.NoError(t, err)
	defer f.Close()

	_, err = f.WriteString(" with a bit more of read")
	require.NoError(t, err)

	b, n, err = fs.Read(file, 0, 512)
	require.NoError(t, err)
	require.True(t, n != 0)
	assert.Equal(t, []byte("ntfs read with a bit more of read"), b[:33])
}

func TestReadFull(t *testing.T) {
	file := filepath.Join(os.TempDir(), "ntfs-read-full.txt")
	err := os.WriteFile(file, []byte("ntfs read from mars to sirius where the whales fly into oblivion"), os.ModePerm)
	require.NoError(t, err)
	defer os.Remove(file)

	fs := NewFS()
	defer fs.Close()

	b, n, err := fs.ReadFull(file)
	assert.NotNil(t, fs)
	require.NoError(t, err)
	require.True(t, n != 0)

	assert.Equal(t, []byte("ntfs read from mars to sirius where the whales fly into oblivion"), b)
}

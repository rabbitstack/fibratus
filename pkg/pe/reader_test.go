//go:build windows
// +build windows

/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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

package pe

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReader(t *testing.T) {
	c := Config{
		Enabled:       true,
		ReadResources: true,
		ReadSymbols:   true,
		ReadSections:  true,
	}
	r := NewReader(c)
	notepad := filepath.Join(os.Getenv("windir"), "notepad.exe")

	pe, err := r.Read(notepad)
	require.NoError(t, err)
	require.NotNil(t, pe)

	require.True(t, pe.NumberOfSections > 0)
	require.True(t, len(pe.Symbols) > 0)
	require.True(t, len(pe.Imports) > 0)
	require.True(t, len(pe.Sections) > 0)

	require.NotEmpty(t, pe.EntryPoint)
	require.NotEmpty(t, pe.ImageBase)
	assert.Contains(t, pe.Symbols, "GetProcAddress")
	assert.Contains(t, pe.Imports, "GDI32.dll")

	assert.Contains(t, pe.VersionResources, "CompanyName")
	assert.Equal(t, "Microsoft Corporation", pe.VersionResources["CompanyName"])
}

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
	kcapver "github.com/rabbitstack/fibratus/pkg/kcap/version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestMetadataMarshal(t *testing.T) {
	now := time.Now()

	pe := &PE{
		NumberOfSections: 7,
		NumberOfSymbols:  10,
		EntryPoint:       "20110",
		ImageBase:        "140000000",
		LinkTime:         now,
		Sections: []Sec{
			{Name: ".text", Size: 132608, Entropy: 6.368381, Md5: "db23dce3911a42e987041d98abd4f7cd"},
			{Name: ".rdata", Size: 35840, Entropy: 5.996976, Md5: "ffa5c960b421ca9887e54966588e97e8"},
		},
		Symbols:          []string{"SelectObject", "GetTextFaceW", "EnumFontsW", "TextOutW", "GetProcessHeap"},
		Imports:          []string{"GDI32.dll", "USER32.dll", "msvcrt.dll", "api-ms-win-core-libraryloader-l1-2-0.dl"},
		VersionResources: map[string]string{"CompanyName": "Microsoft Corporation", "FileDescription": "Notepad", "FileVersion": "10.0.18362.693"},
	}

	b := pe.Marshal()

	newPE := &PE{VersionResources: make(map[string]string)}
	err := newPE.Unmarshal(b, kcapver.PESecV2)
	require.NoError(t, err)

	assert.Equal(t, uint16(7), newPE.NumberOfSections)
	assert.Equal(t, uint32(10), newPE.NumberOfSymbols)
	assert.Equal(t, "20110", newPE.EntryPoint)
	assert.Equal(t, "140000000", newPE.ImageBase)

	assert.Equal(t, now.Day(), newPE.LinkTime.Day())
	assert.Equal(t, now.Minute(), newPE.LinkTime.Minute())

	assert.Len(t, newPE.Sections, 2)

	textSection := newPE.Sections[0]
	assert.Equal(t, ".text", textSection.Name)
	assert.Equal(t, uint32(132608), textSection.Size)
	assert.Equal(t, 6.368381, textSection.Entropy)
	assert.Equal(t, "db23dce3911a42e987041d98abd4f7cd", textSection.Md5)

	assert.Len(t, newPE.Symbols, 5)
	assert.Contains(t, newPE.Symbols, "SelectObject")
	assert.Contains(t, newPE.Symbols, "TextOutW")

	assert.Len(t, newPE.Imports, 4)
	assert.Contains(t, newPE.Imports, "GDI32.dll")
	assert.Contains(t, newPE.Imports, "msvcrt.dll")

	assert.Len(t, newPE.VersionResources, 3)
	assert.Contains(t, newPE.VersionResources, "CompanyName")
	assert.Contains(t, newPE.VersionResources, "FileVersion")

	assert.Equal(t, "10.0.18362.693", newPE.VersionResources["FileVersion"])
	assert.Equal(t, "Microsoft Corporation", newPE.VersionResources["CompanyName"])
	assert.Equal(t, "Notepad", newPE.VersionResources["FileDescription"])
}

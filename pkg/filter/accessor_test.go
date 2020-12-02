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

package filter

import (
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/pe"
	ptypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestPSAccessor(t *testing.T) {
	ps := newPSAccessor()
	kevt := &kevent.Kevent{
		PS: &ptypes.PS{
			Envs: map[string]string{"ALLUSERSPROFILE": "C:\\ProgramData", "OS": "Windows_NT", "ProgramFiles(x86)": "C:\\Program Files (x86)"},
		},
	}

	env, err := ps.get(fields.Field("ps.envs[ALLUSERSPROFILE]"), kevt)
	require.NoError(t, err)
	assert.Equal(t, "C:\\ProgramData", env)

	env, err = ps.get(fields.Field("ps.envs[ALLUSER]"), kevt)
	require.NoError(t, err)
	assert.Equal(t, "C:\\ProgramData", env)

	env, err = ps.get(fields.Field("ps.envs[ProgramFiles]"), kevt)
	require.NoError(t, err)
	assert.Equal(t, "C:\\Program Files (x86)", env)
}

func TestPEAccessor(t *testing.T) {
	pea := newPEAccessor()
	kevt := &kevent.Kevent{
		PS: &ptypes.PS{
			PE: &pe.PE{
				NumberOfSections: 2,
				NumberOfSymbols:  10,
				EntryPoint:       "0x20110",
				ImageBase:        "0x140000000",
				LinkTime:         time.Now(),
				Sections: []pe.Sec{
					{Name: ".text", Size: 132608, Entropy: 6.368381, Md5: "db23dce3911a42e987041d98abd4f7cd"},
					{Name: ".rdata", Size: 35840, Entropy: 5.996976, Md5: "ffa5c960b421ca9887e54966588e97e8"},
				},
				Symbols:          []string{"SelectObject", "GetTextFaceW", "EnumFontsW", "TextOutW", "GetProcessHeap"},
				Imports:          []string{"GDI32.dll", "USER32.dll", "msvcrt.dll", "api-ms-win-core-libraryloader-l1-2-0.dl"},
				VersionResources: map[string]string{"CompanyName": "Microsoft Corporation", "FileDescription": "Notepad", "FileVersion": "10.0.18362.693"},
			},
		},
	}

	entropy, err := pea.get(fields.Field("pe.sections[.text].entropy"), kevt)
	require.NoError(t, err)
	assert.Equal(t, 6.368381, entropy)

	v, err := pea.get(fields.Field("pe.sections[.text].md6"), kevt)
	require.Nil(t, v)

	md5, err := pea.get(fields.Field("pe.sections[.rdata].md5"), kevt)
	require.Nil(t, v)
	assert.Equal(t, "ffa5c960b421ca9887e54966588e97e8", md5)

	company, err := pea.get(fields.Field("pe.resources[CompanyName]"), kevt)
	require.NoError(t, err)
	assert.Equal(t, "Microsoft Corporation", company)
}

func TestCaptureInBrackets(t *testing.T) {
	v, subfield := captureInBrackets("ps.envs[ALLUSERSPROFILE]")
	assert.Equal(t, "ALLUSERSPROFILE", v)
	assert.Empty(t, subfield)

	v, subfield = captureInBrackets("ps.pe.sections[.debug$S].entropy")
	assert.Equal(t, ".debug$S", v)
	assert.Equal(t, fields.SectionEntropy, subfield)
}

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

package kevent

import (
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/stretchr/testify/assert"

	kpars "github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestTemplateUnknownField(t *testing.T) {
	template := "{{ .Seq }} {{NUllField1}} {{.Type}}"
	_, err := NewFormatter(template)
	require.Error(t, err, "NUllField1 is not a known field name. Maybe you meant one of the following fields: .CPU .Category .Cmd .Cwd .Description .Exe .Handles .Host .Kparams .Meta .Pid .Ppid .Process .Seq .Sid .Tid .Timestamp .Type")
}

func TestTemplateEmptyField(t *testing.T) {
	template := "{{ .Seq }} {{}} {{.Type}}"
	_, err := NewFormatter(template)
	require.Error(t, err, "empty field found at position 2")

	template1 := "{{ .Seq }} {{.CPU}} -  ({{.Type}}) -- pid: {{}} {{ .Kparams.Pid }} ({{.Kparams}}) {{ .Meta }}"
	_, err = NewFormatter(template1)
	require.Error(t, err, "empty field found at position 4")
}

func TestTemplateSyntaxError(t *testing.T) {
	template := "{{ .Seq }} {{.CPU}} {.Type}}"
	_, err := NewFormatter(template)
	require.Error(t, err, "template syntax error near field #3: {{ .Seq }} {{.CPU}} {.Type}}")
}

func TestFormat(t *testing.T) {
	template := "{{ .Seq }} {{.CPU}} -  ({{.Type}}) -- pid: {{ .Kparams.Pid }} ({{.Kparams}}) {{ .Meta }}"
	f, err := NewFormatter(template)
	require.NoError(t, err)
	params := Kparams{
		kpars.ProcessID: {Name: kpars.ProcessID, Type: kpars.PID, Value: uint32(876)},
	}
	s := f.Format(&Kevent{CPU: uint8(4), Name: "CreateProcess", Seq: uint64(1999), Kparams: params, Metadata: map[MetadataKey]any{"key1": "value1"}})
	assert.Equal(t, "1999 4 -  (CreateProcess) -- pid: 876 (pid➜ 876) key1: value1", string(s))
}

func TestFormatPS(t *testing.T) {
	template := "{{ .Seq }} {{ .Process }} ({{ .Cwd }}) {{ .Ppid }} ({{ .Sid }})"
	f, err := NewFormatter(template)
	require.NoError(t, err)
	params := Kparams{
		kpars.ProcessID: {Name: kpars.ProcessID, Type: kpars.PID, Value: uint32(876)},
	}
	s := f.Format(&Kevent{
		CPU:     uint8(4),
		Name:    "CreateProcess",
		Seq:     uint64(1999),
		Kparams: params,
		PS: &pstypes.PS{
			Name: "cmd.exe",
			Cwd:  "C:/Windows/System32",
			SID:  "nedo/archrabbit",
			Ppid: 2324,
			Handles: htypes.Handles{
				{Name: "C:/Windows/notepad.exe", Type: "File"},
				{Name: "HKEY_LOCAL_MACHINE/Software", Type: "Key"},
			},
		},
	})
	assert.Equal(t, "1999 cmd.exe (C:/Windows/System32) 2324 (nedo/archrabbit)", string(s))
}

func TestNormalizeTemplate(t *testing.T) {
	assert.Equal(t, "{{.Seq}}   {{.CPU}}", normalizeTemplate("{{ .Seq }}   {{   .CPU   }}"))
}

func TestIsTemplateBalanced(t *testing.T) {
	ok, pos := isTemplateBalanced("{{ .Seq }} {{.CPU}}")
	require.True(t, ok)
	assert.Equal(t, -1, pos)

	ok, pos = isTemplateBalanced("{{ .Seq }} ({{.CPU}}) [] {{.Type}}")
	require.True(t, ok)
	assert.Equal(t, -1, pos)

	ok, pos = isTemplateBalanced("{{ .Seq }} {.CPU}} {{.Type}}")
	require.False(t, ok)
	assert.Equal(t, 2, pos)

	ok, pos = isTemplateBalanced("{.Seq}")
	require.False(t, ok)
	assert.Equal(t, 1, pos)

	ok, pos = isTemplateBalanced("{{ .Seq }} .CPU }}")
	require.False(t, ok)
	assert.Equal(t, 2, pos)

	ok, pos = isTemplateBalanced("{{{ .Seq }} {{.CPU}} {{} {{ .Kparams }} { .Kparams.pid}}")
	require.False(t, ok)
	assert.Equal(t, 1, pos)

	ok, pos = isTemplateBalanced("{{ .Seq }} {{.CPU}} {{} {{ .Kparams }} { .Kparams.pid}}")
	require.False(t, ok)
	assert.Equal(t, 3, pos)

	ok, pos = isTemplateBalanced("({{ .Seq }}) {{.CPU}} {{}} {{ .Kparams }} { .Kparams.pid}}")
	require.False(t, ok)
	assert.Equal(t, 5, pos)

	ok, pos = isTemplateBalanced("{{ .Seq } {{.CPU}} {.Type}}")
	require.False(t, ok)
	assert.Equal(t, 1, pos)

	ok, pos = isTemplateBalanced("{{ .Seq }} {{.CPU}} {.Type}}")
	require.False(t, ok)
	assert.Equal(t, 3, pos)

	ok, pos = isTemplateBalanced("{{ .Seq }} {{.CPU}} -  ({{.Type}}) -- pid: {{]} {{ .Kparams.Pid }} ({{.Kparams}}) {{ .Meta }}")
	require.False(t, ok)
	assert.Equal(t, 4, pos)
}

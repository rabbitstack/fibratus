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

package event

import (
	"github.com/rabbitstack/fibratus/pkg/event/params"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/stretchr/testify/assert"

	"testing"

	"github.com/stretchr/testify/require"
)

func TestTemplateUnknownField(t *testing.T) {
	template := "{{ .Seq }} {{NUllField1}} {{.Type}}"
	_, err := NewFormatter(template)
	require.Error(t, err, "NUllField1 is not a known field name. Maybe you meant one of the following fields: .CPU .Category .Cmd .Cwd .Description .Exe .Handles .Host .Params .Meta .Pid .Ppid .Process .Seq .Sid .Tid .Timestamp .Type")
}

func TestTemplateEmptyField(t *testing.T) {
	template := "{{ .Seq }} {{}} {{.Type}}"
	_, err := NewFormatter(template)
	require.Error(t, err, "empty field found at position 2")

	template1 := "{{ .Seq }} {{.CPU}} -  ({{.Type}}) -- pid: {{}} {{ .Params.Pid }} ({{.Params}}) {{ .Meta }}"
	_, err = NewFormatter(template1)
	require.Error(t, err, "empty field found at position 4")
}

func TestTemplateSyntaxError(t *testing.T) {
	template := "{{ .Seq }} {{.CPU}} {.Type}}"
	_, err := NewFormatter(template)
	require.Error(t, err, "template syntax error near field #3: {{ .Seq }} {{.CPU}} {.Type}}")
}

func TestFormat(t *testing.T) {
	template := "{{ .Seq }} {{.CPU}} -  ({{.Type}}) -- pid: {{ .Params.Pid }} ({{.Params}}) {{ .Meta }}"
	f, err := NewFormatter(template)
	require.NoError(t, err)
	pars := Params{
		params.ProcessID: {Name: params.ProcessID, Type: params.PID, Value: uint32(876)},
	}
	s := f.Format(&Event{CPU: uint8(4), Type: CreateProcess, Seq: uint64(1999), Params: pars, Metadata: map[MetadataKey]any{"key1": "value1"}})
	assert.Equal(t, "1999 4 -  (CreateProcess) -- pid: 876 (pid➜ 876) key1: value1", string(s))
}

func TestFormatPS(t *testing.T) {
	template := "{{ .Seq }} {{ .Process }} ({{ .Cwd }}) {{ .Ppid }} ({{ .Sid }})"
	f, err := NewFormatter(template)
	require.NoError(t, err)
	pars := Params{
		params.ProcessID: {Name: params.ProcessID, Type: params.PID, Value: uint32(876)},
	}
	s := f.Format(&Event{
		CPU:    uint8(4),
		Seq:    uint64(1999),
		Params: pars,
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
	tests := []struct {
		name    string
		input   string
		wantOK  bool
		wantPos int
	}{
		{
			name:    "balanced templates",
			input:   "{{ .Seq }} {{.CPU}}",
			wantOK:  true,
			wantPos: -1,
		},
		{
			name:    "balanced templates with other delimiters",
			input:   "{{ .Seq }} ({{.CPU}}) [] {{.Type}}",
			wantOK:  true,
			wantPos: -1,
		},
		{
			name:    "single opening brace",
			input:   "{{ .Seq }} {.CPU}} {{.Type}}",
			wantOK:  false,
			wantPos: 2,
		},
		{
			name:    "single template",
			input:   "{.Seq}",
			wantOK:  false,
			wantPos: 1,
		},
		{
			name:    "unmatched closing braces",
			input:   "{{ .Seq }} .CPU }}",
			wantOK:  false,
			wantPos: 2,
		},
		{
			name:    "triple opening brace",
			input:   "{{{ .Seq }} {{.CPU}} {{} {{ .Params }} { .Params.pid}}",
			wantOK:  false,
			wantPos: 1,
		},
		{
			name:    "empty template",
			input:   "{{ .Seq }} {{.CPU}} {{} {{ .Params }} { .Params.pid}}",
			wantOK:  false,
			wantPos: 3,
		},
		{
			name:    "empty template with other delimiters",
			input:   "({{ .Seq }}) {{.CPU}} {{}} {{ .Params }} { .Params.pid}}",
			wantOK:  false,
			wantPos: 5,
		},
		{
			name:    "malformed closing delimiter",
			input:   "{{ .Seq } {{.CPU}} {.Type}}",
			wantOK:  false,
			wantPos: 1,
		},
		{
			name:    "unmatched closing brace",
			input:   "{{ .Seq }} {{.CPU}} {.Type}}",
			wantOK:  false,
			wantPos: 3,
		},
		{
			name:    "malformed template in complex input",
			input:   "{{ .Seq }} {{.CPU}} -  ({{.Type}}) -- pid: {{]} {{ .Params.Pid }} ({{.Params}}) {{ .Meta }}",
			wantOK:  false,
			wantPos: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, pos := isTemplateBalanced(tt.input)

			require.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantPos, pos)
		})
	}
}

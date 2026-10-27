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
	"testing"

	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/stretchr/testify/assert"
)

func TestParams(t *testing.T) {
	pars := ParamsOf(
		NewParam(params.FileObject, params.Uint64, params.U64(uint64(18446738026482168384))),
		NewParam(params.ThreadID, params.Uint32, params.U32(uint32(1484))),
		NewParam(params.FileOffset, params.Uint64, params.U64(uint64(1223456))),
		NewParam(params.FilePath, params.Path, params.Str("/usr/bin/bash")),
		NewParam(params.ProcessID, params.Uint32, params.U32(uint32(5))),
	)

	assert.True(t, pars.Contains(params.FileObject))
	assert.False(t, pars.Contains(params.ProcessName))

	assert.Equal(t, "/usr/bin/bash", pars.GetStringByName(params.FilePath))

	// getters return the zero value for the absent parameters and the mismatching kinds
	assert.Equal(t, "", pars.GetStringByName(params.FileObject))
	assert.Equal(t, uint32(0), pars.GetUint32ByName(params.ProcessName))
	assert.Equal(t, "", pars.GetString(-1))

	assert.Equal(t, 5, pars.Len())

	pars.Remove(params.ThreadID)

	assert.False(t, pars.Contains(params.ThreadID))
	assert.Equal(t, 4, pars.Len())

	pars.SetByName(params.FilePath, params.Str("/usr/bin/zsh"))
	assert.Equal(t, "/usr/bin/zsh", pars.GetStringByName(params.FilePath))
}

func TestParamsSchemaIntegrity(t *testing.T) {
	for _, typ := range AllTypes() {
		info := GetTypeInfo(typ)
		assert.Equal(t, len(info.Params), info.ParamCount(), typ.String())
		seen := make(map[string]struct{}, len(info.Params))
		for _, pi := range info.Params {
			assert.NotEmptyf(t, pi.Name, "%s declares a parameter without name", typ)
			_, dup := seen[pi.Name]
			assert.Falsef(t, dup, "%s declares duplicate parameter %s", typ, pi.Name)
			seen[pi.Name] = struct{}{}
		}
		// freshly created parameters have a slot per schema entry, but no values
		pars := NewParams(typ)
		assert.Equal(t, len(info.Params), pars.Size(), typ.String())
		assert.Equal(t, 0, pars.Len(), typ.String())
	}
}

func TestParamsSetAppendRename(t *testing.T) {
	pars := ParamsOf(
		NewParam(params.ProcessID, params.PID, params.U32(10)),
		NewParam(params.FilePath, params.Path, params.Str("/etc/passwd")),
	)

	// assigning an unknown name appends a parameter and infers its type from the value
	pars.SetByName("dyn", params.U64(7))
	assert.Equal(t, 3, pars.Len())
	assert.Equal(t, params.Uint64, pars.Type(pars.Index("dyn")))
	assert.Equal(t, uint64(7), pars.GetUint64ByName("dyn"))

	// append overrides the type
	pars.Append("dyn2", params.Address, params.U64(0xff))
	assert.Equal(t, params.Address, pars.Type(pars.Index("dyn2")))

	// out-of-range indexes and absent names yield default values
	assert.Equal(t, uint32(0), pars.GetUint32(100))
	assert.Equal(t, "", pars.GetStringByName("nope"))
	assert.False(t, pars.Contains("nope"))

	assert.True(t, pars.Rename(params.FilePath, "path"))
	assert.False(t, pars.Contains(params.FilePath))
	assert.Equal(t, "/etc/passwd", pars.GetStringByName("path"))

	pars.Remove("path")
	assert.False(t, pars.Contains("path"))
	assert.Equal(t, 3, pars.Len())

	// kind mismatch returns the zero value
	assert.Equal(t, "", pars.GetStringByName(params.ProcessID))
	assert.Equal(t, uint32(10), pars.GetUint32ByName(params.ProcessID))
}

func TestParamsSharedSchemaNotMutated(t *testing.T) {
	typ := AllTypes()[0]
	if len(GetTypeInfo(typ).Params) == 0 {
		t.Skip("no schema")
	}
	name := GetTypeInfo(typ).Params[0].Name
	a := NewParams(typ)
	a.Rename(name, "renamed")
	a.Append("extra", params.Uint32, params.U32(1))
	b := NewParams(typ)
	assert.Equal(t, name, GetTypeInfo(typ).Params[0].Name)
	assert.GreaterOrEqual(t, b.Index(name), 0)
	assert.Equal(t, -1, b.Index("extra"))
}

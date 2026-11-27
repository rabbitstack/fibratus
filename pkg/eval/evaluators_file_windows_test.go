/*
 * Copyright 2026 by Nedim Sabic Sabic
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

package eval

import (
	"testing"

	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileAndRegistryEvaluatorsInvariants(t *testing.T) {
	var flds []Field
	flds = append(flds, evaluatedFields(fields.SourceFile)...)
	flds = append(flds, evaluatedFields(fields.SourceRegistry)...)
	require.GreaterOrEqual(t, len(flds), 34)

	str := func(name, v string) event.Param { return event.NewParam(name, params.String, params.Str(v)) }
	u32 := func(name string, v uint32) event.Param { return event.NewParam(name, params.Uint32, params.U32(v)) }
	u64 := func(name string, v uint64) event.Param { return event.NewParam(name, params.Uint64, params.U64(v)) }

	file := func(typ event.Type, ps ...event.Param) *event.Event {
		return &event.Event{Type: typ, PID: 1023, Params: event.ParamsOf(ps...)}
	}
	create := file(event.CreateFile,
		str(params.FilePath, `C:\Users\bunny\payload.tar.gz`), str(params.NTStatus, "success"),
		str(params.FileOperation, "CREATE"), str(params.FileShareMask, "rw-"), str(params.FileType, "File"),
		u64(params.FileObject, 0xffffd0e1), u64(params.FileKey, 7), u32(params.ProcessID, 4096))
	info := func(class uint32, extra uint64) *event.Event {
		return file(event.SetFileInformation,
			str(params.FilePath, `C:\noext`), u32(params.FileInfoClass, class), u64(params.FileExtraInfo, extra))
	}
	reg := func(typ event.Type, ps ...event.Param) *event.Event {
		return &event.Event{Type: typ, PID: 1023, Params: event.ParamsOf(ps...)}
	}

	evts := map[string]*event.Event{
		"empty":       {},
		"create":      create,
		"create bare": file(event.CreateFile),
		"read":        file(event.ReadFile, u64(params.FileOffset, 512), u32(params.FileIoSize, 4096), str(params.FilePath, `D:\a.b\c`)),
		"map view":    file(event.MapViewOfSection, str(params.FileViewBase, "7ffe0000"), u64(params.FileViewSize, 8192), str(params.FileViewSectionType, "IMAGE"), str(params.MemProtect, "READONLY")),
		"alloc size":  info(fs.AllocationClass, 99),
		"eof size":    info(fs.EOFClass, 100),
		"delete":      info(fs.DispositionClass, 1),
		"not delete":  info(fs.DispositionClass, 0),
		"other class": info(1, 5),
		"set value":   reg(event.RegSetValue, str(params.RegPath, `HKEY_LOCAL_MACHINE\SOFTWARE\Run\Updater`), str(params.RegValue, "Updater"), str(params.RegData, "evil.exe"), str(params.RegValueType, "REG_SZ"), str(params.NTStatus, "success")),
		"create key":  reg(event.RegCreateKey, str(params.RegPath, `HKEY_LOCAL_MACHINE\SOFTWARE\Run`), str(params.RegKCB, "ffff01")),
		"reg bare":    reg(event.RegSetValue),
		"query value": reg(event.RegQueryValue, str(params.RegPath, `HKEY_USERS\x\y`), str(params.RegValue, "y")),
	}

	x := newExtractor(flds, nil, nil)
	for _, f := range x.fields {
		require.NotNil(t, f.eval, "%s has no evaluator", f.String())
	}
	assertEvaluatorInvariants(t, x, flds, evts)
}

func TestFileMetadataResolverRunsOnlyWhenReached(t *testing.T) {
	var calls int
	r := &Resolvers{FileMeta: NewResolver("file_metadata", func(string) *fs.FileInfo { calls++; return &fs.FileInfo{IsDLL: true} })}
	evt := &event.Event{Type: event.CreateFile, PID: 1023, Params: event.ParamsOf(
		event.NewParam(params.FilePath, params.String, params.Str(`C:\a\b.dll`)),
		event.NewParam(params.FileOperation, params.String, params.Str("CREATE")),
		event.NewParam(params.NTStatus, params.String, params.Str("success")),
	)}
	if !evt.IsCreateDisposition() || !evt.IsSuccess() {
		t.Skip("the synthetic event isn't a successful create")
	}

	run := func(expr string) bool {
		calls = 0
		p, err := NewProgram("t", expr, WithResolvers(r))
		require.NoError(t, err)
		ctx := AcquireEvalCtx()
		defer ctx.Release()
		return p.Eval(evt, ctx)
	}
	assert.False(t, run(`file.extension = '.exe' and file.is_dll = true`))
	assert.Zero(t, calls)
	assert.True(t, run(`file.extension = '.dll' and file.is_dll = true and file.is_driver = false`))
	assert.Equal(t, 1, calls)
}

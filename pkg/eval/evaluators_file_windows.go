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
	"path/filepath"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/fs"
)

// fileEvaluator returns the file.* evaluator of the field, or nil if the field
// isn't one of them. The file.is_dll, file.is_driver and file.is_executable
// fields query the file metadata store through its resolver.
func fileEvaluator(f Field) Evaluator {
	b := evaluatorBase(f)
	switch f.Name {
	case fields.FileIsDLL:
		return fileMeta(f, func(fi *fs.FileInfo) bool { return fi.IsDLL })
	case fields.FileIsDriver:
		return fileMeta(f, func(fi *fs.FileInfo) bool { return fi.IsDriver })
	case fields.FileIsExecutable:
		return fileMeta(f, func(fi *fs.FileInfo) bool { return fi.IsExecutable })

	case fields.FilePath:
		return stringParam(f, params.FilePath)
	case fields.FileShareMask, fields.FileShareMode:
		return stringParam(f, params.FileShareMask)
	case fields.FileOperation:
		return stringParam(f, params.FileOperation)
	case fields.FileType:
		return stringParam(f, params.FileType)
	case fields.FileViewBase:
		return stringParam(f, params.FileViewBase)
	case fields.FileViewType:
		return stringParam(f, params.FileViewSectionType)
	case fields.FileViewProtection:
		return stringParam(f, params.MemProtect)
	case fields.FileInfoClass:
		return stringParam(f, params.FileInfoClass)

	case fields.FileIOSize:
		return uint32Param(f, params.FileIoSize)
	case fields.FilePID:
		return uint32Param(f, params.ProcessID)
	case fields.FileOffset:
		return uint64Param(f, params.FileOffset)
	case fields.FileObject:
		return uint64Param(f, params.FileObject)
	case fields.FileViewSize:
		return uint64Param(f, params.FileViewSize)
	case fields.FileKey:
		return uint64Param(f, params.FileKey)

	case fields.FilePathStem:
		return &StringEvaluator{EvaluatorBase: b, Get: always(func(e *event.Event) string {
			path := e.GetParamAsString(params.FilePath)
			n := strings.LastIndexByte(path, '.')
			if n == -1 {
				return path
			}
			return path[:n]
		})}
	case fields.FileName:
		return &StringEvaluator{EvaluatorBase: b, Get: always(func(e *event.Event) string {
			return filepath.Base(e.GetParamAsString(params.FilePath))
		})}
	case fields.FileExtension:
		return &StringEvaluator{EvaluatorBase: b, Get: always(func(e *event.Event) string {
			return filepath.Ext(e.GetParamAsString(params.FilePath))
		})}
	case fields.FileAttributes:
		return &StringSliceEvaluator{EvaluatorBase: b, Get: always(func(e *event.Event) []string {
			return e.GetFlagsAsSlice(params.FileAttributes)
		})}
	case fields.FileStatus:
		return &StringEvaluator{EvaluatorBase: b, Get: optional(func(e *event.Event) (string, bool) {
			if e.Type != event.CreateFile {
				return "", false
			}
			return e.GetParamAsString(params.NTStatus), true
		})}
	case fields.FileInfoAllocationSize:
		return &Uint64Evaluator{EvaluatorBase: b, Get: optional(func(e *event.Event) (uint64, bool) {
			if e.Params.GetUint32ByName(params.FileInfoClass) != fs.AllocationClass {
				return 0, false
			}
			return param(e, params.FileExtraInfo, event.Params.GetUint64ByName), true
		})}
	case fields.FileInfoEOFSize:
		return &Uint64Evaluator{EvaluatorBase: b, Get: optional(func(e *event.Event) (uint64, bool) {
			if e.Params.GetUint32ByName(params.FileInfoClass) != fs.EOFClass {
				return 0, false
			}
			return param(e, params.FileExtraInfo, event.Params.GetUint64ByName), true
		})}
	case fields.FileInfoIsDispositionDeleteFile:
		return &BoolEvaluator{EvaluatorBase: b, Get: always(func(e *event.Event) bool {
			return e.Params.GetUint32ByName(params.FileInfoClass) == fs.DispositionClass &&
				e.Params.GetUint64ByName(params.FileExtraInfo) > 0
		})}
	}
	return nil
}

// fileMeta reads a property of the file the event creates. The file metadata
// are only looked up for the events that create a file successfully.
func fileMeta(f Field, get func(*fs.FileInfo) bool) Evaluator {
	return &BoolEvaluator{EvaluatorBase: evaluatorBase(f), Get: func(ctx *EvalCtx) (bool, bool) {
		e := ctx.Evt
		var file *fs.FileInfo
		if e.IsCreateDisposition() && e.IsSuccess() {
			file = ctx.Resolvers.FileMeta.Of(ctx, e.GetParamAsString(params.FilePath))
		}
		return file != nil && get(file), true
	}}
}

// registryEvaluator returns the registry.* evaluator of the field, or nil if the
// field isn't one of them.
func registryEvaluator(f Field) Evaluator {
	b := evaluatorBase(f)
	switch f.Name {
	case fields.RegistryPath:
		return stringParam(f, params.RegPath)
	case fields.RegistryKCB:
		return stringParam(f, params.RegKCB)
	case fields.RegistryData:
		return stringParam(f, params.RegData)
	case fields.RegistryStatus:
		return stringParam(f, params.NTStatus)

	case fields.RegistryKeyName:
		return &StringEvaluator{EvaluatorBase: b, Get: always(func(e *event.Event) string {
			path := e.GetParamAsString(params.RegPath)
			if e.IsRegSetValue() {
				path = strings.TrimSuffix(path, e.GetParamAsString(params.RegValue))
			}
			return filepath.Base(path)
		})}
	case fields.RegistryValue:
		return &StringEvaluator{EvaluatorBase: b, Get: optional(func(e *event.Event) (string, bool) {
			if !e.IsRegSetValue() {
				return "", false
			}
			return e.GetParamAsString(params.RegValue), true
		})}
	case fields.RegistryValueType:
		return &StringEvaluator{EvaluatorBase: b, Get: always(func(e *event.Event) string {
			return param(e, params.RegValueType, event.Params.GetStringByName)
		})}
	}
	return nil
}

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
	"net"
	"path/filepath"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
)

// missingEnv is what an environment variable that doesn't exist reads as:
// the empty string.
func missingEnv() (any, bool) { return "", true }

// platformEvaluator returns the evaluator of the fields that are read on Linux
// and aren't shared with the other platforms, or nil if the field isn't one of
// them.
func platformEvaluator(f Field) Evaluator {
	b := evaluatorBase(f)
	switch f.Name {
	case fields.EvtRetval:
		return &Int64Evaluator{EvaluatorBase: b, Get: fromParam(params.Retval, event.Params.GetInt64ByName)}
	case fields.EvtSyscallID:
		return &Uint32Evaluator{EvaluatorBase: b, Get: fromParam(params.SyscallID, event.Params.GetUint32ByName)}

	// the identity is the one of the process state, or the one of
	// the event parameter if the state isn't available
	case fields.PsUID:
		return &Uint32Evaluator{EvaluatorBase: b, Get: always(func(e *event.Event) uint32 {
			if e.PS != nil {
				return e.PS.UID
			}
			return param(e, params.UID, event.Params.GetUint32ByName)
		})}
	case fields.PsGID:
		return &Uint32Evaluator{EvaluatorBase: b, Get: always(func(e *event.Event) uint32 {
			if e.PS != nil {
				return e.PS.GID
			}
			return param(e, params.GID, event.Params.GetUint32ByName)
		})}
	case fields.PsSignal:
		return &Int64Evaluator{EvaluatorBase: b, Get: always(func(e *event.Event) int64 {
			return int64(param(e, params.Signal, event.Params.GetInt32ByName))
		})}
	case fields.PsTargetPID:
		return &Int64Evaluator{EvaluatorBase: b, Get: fromParam(params.TargetProcessID, event.Params.GetInt64ByName)}
	case fields.PsPtraceRequest:
		return &Int64Evaluator{EvaluatorBase: b, Get: fromParam(params.PtraceRequest, event.Params.GetInt64ByName)}
	case fields.PsPrctlOption:
		return &Int64Evaluator{EvaluatorBase: b, Get: fromParam(params.PrctlOption, event.Params.GetInt64ByName)}
	case fields.PsCloneFlags:
		return &Uint64Evaluator{EvaluatorBase: b, Get: fromParam(params.CloneFlags, event.Params.GetUint64ByName)}

	case fields.FilePath:
		return &StringEvaluator{EvaluatorBase: b, Get: always(filePath)}
	case fields.FilePathStem:
		return &StringEvaluator{EvaluatorBase: b, Get: always(func(e *event.Event) string { return pathStem(filePath(e)) })}
	case fields.FileName:
		return &StringEvaluator{EvaluatorBase: b, Get: always(func(e *event.Event) string { return filepath.Base(filePath(e)) })}
	case fields.FileExtension:
		return &StringEvaluator{EvaluatorBase: b, Get: always(func(e *event.Event) string { return filepath.Ext(filePath(e)) })}
	case fields.FilePathTarget:
		return &StringEvaluator{EvaluatorBase: b, Get: always(func(e *event.Event) string { return e.GetParamAsString(params.FileNewPath) })}
	case fields.FileDirFD:
		return &Int64Evaluator{EvaluatorBase: b, Get: fromParam(params.DirFD, event.Params.GetInt64ByName)}
	case fields.FileFD:
		return &Int64Evaluator{EvaluatorBase: b, Get: fromParam(params.FD, event.Params.GetInt64ByName)}
	case fields.FileFlags:
		return &Uint64Evaluator{EvaluatorBase: b, Get: fromParam(params.FileFlags, event.Params.GetUint64ByName)}
	case fields.FileMode:
		return &Uint64Evaluator{EvaluatorBase: b, Get: fromParam(params.FileMode, event.Params.GetUint64ByName)}

	case fields.NetDIP:
		return &IPEvaluator{EvaluatorBase: b, Get: fromParam[net.IP](params.NetDIP, event.Params.GetIPByName)}
	case fields.NetSIP:
		return &IPEvaluator{EvaluatorBase: b, Get: fromParam[net.IP](params.NetSIP, event.Params.GetIPByName)}
	case fields.NetDport:
		return &Uint16Evaluator{EvaluatorBase: b, Get: fromParam(params.NetDport, event.Params.GetUint16ByName)}
	case fields.NetSport:
		return &Uint16Evaluator{EvaluatorBase: b, Get: fromParam(params.NetSport, event.Params.GetUint16ByName)}
	case fields.NetFamily:
		return &Uint16Evaluator{EvaluatorBase: b, Get: fromParam(params.SockFamily, event.Params.GetUint16ByName)}
	case fields.NetUnixPath:
		return &StringEvaluator{EvaluatorBase: b, Get: always(func(e *event.Event) string { return e.GetParamAsString(params.SockPath) })}
	case fields.NetFD:
		return &Int64Evaluator{EvaluatorBase: b, Get: fromParam(params.FD, event.Params.GetInt64ByName)}

	case fields.MemBaseAddress:
		return &Uint64Evaluator{EvaluatorBase: b, Get: fromParam(params.MemBaseAddress, event.Params.GetUint64ByName)}
	case fields.MemRegionSize:
		return &Uint64Evaluator{EvaluatorBase: b, Get: fromParam(params.MemRegionSize, event.Params.GetUint64ByName)}
	case fields.MemProtection:
		return &Uint32Evaluator{EvaluatorBase: b, Get: fromParam(params.MemProtect, event.Params.GetUint32ByName)}
	case fields.MemMmapFlags:
		return &Uint64Evaluator{EvaluatorBase: b, Get: fromParam(params.MmapFlags, event.Params.GetUint64ByName)}
	case fields.MemMmapFD:
		return &Int64Evaluator{EvaluatorBase: b, Get: fromParam(params.FD, event.Params.GetInt64ByName)}
	case fields.MemMmapOffset:
		return &Uint64Evaluator{EvaluatorBase: b, Get: fromParam(params.MmapOffset, event.Params.GetUint64ByName)}
	case fields.MemTargetPID:
		return &Int64Evaluator{EvaluatorBase: b, Get: fromParam(params.TargetProcessID, event.Params.GetInt64ByName)}

	case fields.ThreadTID:
		return &Uint32Evaluator{EvaluatorBase: b, Get: always(func(e *event.Event) uint32 { return e.Tid })}
	case fields.ThreadPID:
		return &Uint32Evaluator{EvaluatorBase: b, Get: always(func(e *event.Event) uint32 { return e.PID })}
	}
	return nil
}

func filePath(e *event.Event) string { return e.GetParamAsString(params.FilePath) }

// pathStem returns the path without the extension.
func pathStem(p string) string {
	n := strings.LastIndexByte(p, '.')
	if n == -1 {
		return p
	}
	return p[:n]
}

//go:build linux

/*
 * Copyright 2026 by Mostafa Moradian
 * https://www.fibratus.io
 * All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
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
	"path/filepath"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/rabbitstack/fibratus/pkg/ps"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
)

// GetAccessors returns the accessors available on Linux.
func GetAccessors() []Accessor {
	return []Accessor{
		newEventAccessor(),
		newPSAccessor(nil),
		newFileAccessor(),
		newNetworkAccessor(),
		newMemAccessor(),
		newThreadAccessor(),
	}
}

// platformEvtValue resolves evt fields available only on Linux.
func platformEvtValue(f Field, evt *event.Event) (params.Value, error) {
	switch f.Name {
	case fields.EvtRetval:
		return evt.Params.GetInt64(params.Retval)
	case fields.EvtSyscall:
		return evt.Params.GetUint32(params.SyscallID)
	case fields.EvtTruncated:
		return evt.Params.TryGetUint32(params.Truncated) != 0, nil
	default:
		return nil, nil
	}
}

func getParentPs(e *event.Event) *pstypes.PS {
	if e.PS == nil {
		return nil
	}
	return e.PS.Parent
}

type psAccessor struct {
	psnap ps.Snapshotter
}

func (psAccessor) SetFields([]Field)            {}
func (psAccessor) SetSegments([]fields.Segment) {}
func (psAccessor) IsFieldAccessible(e *event.Event) bool {
	return e.PS != nil || e.Category == event.Process
}

func newPSAccessor(psnap ps.Snapshotter) Accessor { return &psAccessor{psnap: psnap} }

func (a *psAccessor) Get(f Field, e *event.Event) (params.Value, error) {
	switch f.Name {
	case fields.PsPid:
		return e.PID, nil
	case fields.PsPpid:
		if e.PS == nil {
			return nil, ErrPsNil
		}
		return e.PS.Ppid, nil
	case fields.PsName:
		if e.PS == nil {
			return nil, ErrPsNil
		}
		return e.PS.Name, nil
	case fields.PsCmdline:
		if e.PS == nil {
			return nil, ErrPsNil
		}
		return e.PS.Cmdline, nil
	case fields.PsExe:
		if e.PS == nil {
			return nil, ErrPsNil
		}
		return e.PS.Exe, nil
	case fields.PsArgs:
		if e.PS == nil {
			return nil, ErrPsNil
		}
		return e.PS.Args, nil
	case fields.PsCwd:
		if e.PS == nil {
			return nil, ErrPsNil
		}
		return e.PS.Cwd, nil
	case fields.PsUsername:
		if e.PS == nil {
			return nil, ErrPsNil
		}
		return e.PS.Username, nil
	case fields.PsUID:
		if e.PS != nil {
			return e.PS.UID, nil
		}
		return e.Params.GetUint32(params.UID)
	case fields.PsGID:
		if e.PS != nil {
			return e.PS.GID, nil
		}
		return e.Params.GetUint32(params.GID)
	case fields.PsUUID:
		if e.PS == nil {
			return nil, ErrPsNil
		}
		return e.PS.UUID(), nil
	case fields.PsEnvs:
		if e.PS == nil {
			return nil, ErrPsNil
		}
		if f.Arg != "" {
			if v, ok := e.PS.Envs[f.Arg]; ok {
				return v, nil
			}
			for k, v := range e.PS.Envs {
				if strings.HasPrefix(k, f.Arg) {
					return v, nil
				}
			}
			return "", nil
		}
		envs := make([]string, 0, len(e.PS.Envs))
		for k, v := range e.PS.Envs {
			envs = append(envs, k+":"+v)
		}
		return envs, nil
	case fields.PsParentPid:
		parent := getParentPs(e)
		if parent == nil {
			return nil, ErrPsNil
		}
		return parent.PID, nil
	case fields.PsParentName:
		parent := getParentPs(e)
		if parent == nil {
			return nil, ErrPsNil
		}
		return parent.Name, nil
	case fields.PsParentCmdline:
		parent := getParentPs(e)
		if parent == nil {
			return nil, ErrPsNil
		}
		return parent.Cmdline, nil
	case fields.PsParentExe:
		parent := getParentPs(e)
		if parent == nil {
			return nil, ErrPsNil
		}
		return parent.Exe, nil
	case fields.PsParentArgs:
		parent := getParentPs(e)
		if parent == nil {
			return nil, ErrPsNil
		}
		return parent.Args, nil
	case fields.PsParentCwd:
		parent := getParentPs(e)
		if parent == nil {
			return nil, ErrPsNil
		}
		return parent.Cwd, nil
	case fields.PsParentUsername:
		parent := getParentPs(e)
		if parent == nil {
			return nil, ErrPsNil
		}
		return parent.Username, nil
	case fields.PsParentUUID:
		parent := getParentPs(e)
		if parent == nil {
			return nil, ErrPsNil
		}
		return parent.UUID(), nil
	case fields.PsParentEnvs:
		parent := getParentPs(e)
		if parent == nil {
			return nil, ErrPsNil
		}
		envs := make([]string, 0, len(parent.Envs))
		for k, v := range parent.Envs {
			envs = append(envs, k+":"+v)
		}
		return envs, nil
	case fields.PsSignal:
		sig, err := e.Params.GetInt32(params.Signal)
		if err != nil {
			return nil, err
		}
		return int64(sig), nil
	case fields.PsTargetPID:
		return e.Params.GetUint64(params.TargetProcessID)
	case fields.PsPtraceRequest:
		return e.Params.GetInt64(params.PtraceRequest)
	case fields.PsPrctlOption:
		return e.Params.GetInt64(params.PrctlOption)
	case fields.PsCloneFlags:
		return e.Params.GetUint64(params.CloneFlags)
	default:
		return nil, nil
	}
}

type fileAccessor struct{}

func (fileAccessor) SetFields([]Field)                     {}
func (fileAccessor) SetSegments([]fields.Segment)          {}
func (fileAccessor) IsFieldAccessible(e *event.Event) bool { return e.Category == event.File }
func newFileAccessor() Accessor                            { return &fileAccessor{} }

func (*fileAccessor) Get(f Field, e *event.Event) (params.Value, error) {
	switch f.Name {
	case fields.FilePath:
		return e.GetParamAsString(params.FilePath), nil
	case fields.FilePathStem:
		return pathStem(e.GetParamAsString(params.FilePath)), nil
	case fields.FileName:
		return filepath.Base(e.GetParamAsString(params.FilePath)), nil
	case fields.FileExtension:
		return filepath.Ext(e.GetParamAsString(params.FilePath)), nil
	case fields.FileNewPath:
		return e.GetParamAsString(params.FileNewPath), nil
	case fields.FileDirFD:
		return e.Params.GetInt64(params.DirFD)
	case fields.FileFD:
		return e.Params.GetInt64(params.FD)
	case fields.FileFlags:
		return e.Params.GetUint64(params.FileFlags)
	case fields.FileMode:
		return e.Params.GetUint64(params.FileMode)
	case fields.FileTruncated:
		// for file events both truncation bits designate a clipped
		// path: the source path or the rename destination
		return e.Params.TryGetUint32(params.Truncated) != 0, nil
	default:
		return nil, nil
	}
}

type networkAccessor struct{}

func (networkAccessor) SetFields([]Field)                     {}
func (networkAccessor) SetSegments([]fields.Segment)          {}
func (networkAccessor) IsFieldAccessible(e *event.Event) bool { return e.Category == event.Net }
func newNetworkAccessor() Accessor                            { return &networkAccessor{} }

func (*networkAccessor) Get(f Field, e *event.Event) (params.Value, error) {
	switch f.Name {
	case fields.NetDIP:
		return e.Params.GetIP(params.NetDIP)
	case fields.NetSIP:
		return e.Params.GetIP(params.NetSIP)
	case fields.NetDport:
		return e.Params.GetUint16(params.NetDport)
	case fields.NetSport:
		return e.Params.GetUint16(params.NetSport)
	case fields.NetFamily:
		return e.Params.GetUint16(params.SockFamily)
	case fields.NetPath:
		return e.GetParamAsString(params.SockPath), nil
	case fields.NetFD:
		return e.Params.GetInt64(params.FD)
	default:
		return nil, nil
	}
}

type memAccessor struct{}

func (memAccessor) SetFields([]Field)                     {}
func (memAccessor) SetSegments([]fields.Segment)          {}
func (memAccessor) IsFieldAccessible(e *event.Event) bool { return e.Category == event.Mem }
func newMemAccessor() Accessor                            { return &memAccessor{} }

func (*memAccessor) Get(f Field, e *event.Event) (params.Value, error) {
	switch f.Name {
	case fields.MemBaseAddress:
		return e.Params.GetUint64(params.MemBaseAddress)
	case fields.MemRegionSize:
		return e.Params.GetUint64(params.MemRegionSize)
	case fields.MemProtection:
		return e.Params.GetUint32(params.MemProtect)
	case fields.MemFlags:
		return e.Params.GetUint64(params.MmapFlags)
	case fields.MemFD:
		return e.Params.GetInt64(params.FD)
	case fields.MemOffset:
		return e.Params.GetUint64(params.MmapOffset)
	case fields.MemTargetPID:
		return e.Params.GetUint64(params.TargetProcessID)
	default:
		return nil, nil
	}
}

type threadAccessor struct{}

func (threadAccessor) SetFields([]Field)            {}
func (threadAccessor) SetSegments([]fields.Segment) {}
func (threadAccessor) IsFieldAccessible(e *event.Event) bool {
	return e.IsCreateThread()
}
func newThreadAccessor() Accessor { return &threadAccessor{} }

func (*threadAccessor) Get(f Field, e *event.Event) (params.Value, error) {
	switch f.Name {
	case fields.ThreadTID:
		return e.Tid, nil
	case fields.ThreadPID:
		return e.PID, nil
	default:
		return nil, nil
	}
}

func pathStem(p string) string {
	n := strings.LastIndexByte(p, '.')
	if n == -1 {
		return p
	}
	return p[:n]
}

func (f *filter) pruneUnusedAccessors() {
	removeEvtAccessor := true
	removePsAccessor := true
	removeFileAccessor := true
	removeNetworkAccessor := true
	removeMemAccessor := true
	removeThreadAccessor := true

	for _, field := range f.fields {
		switch {
		case field.Name.IsEvtField() || field.Name.IsKevtField():
			removeEvtAccessor = false
		case field.Name.IsPsField():
			removePsAccessor = false
		case field.Name.IsFileField():
			removeFileAccessor = false
		case field.Name.IsNetworkField():
			removeNetworkAccessor = false
		case field.Name.IsMemField():
			removeMemAccessor = false
		case field.Name.IsThreadField():
			removeThreadAccessor = false
		}
	}

	if removeEvtAccessor {
		f.removeAccessor(&evtAccessor{})
	}
	if removePsAccessor {
		f.removeAccessor(&psAccessor{})
	}
	if removeFileAccessor {
		f.removeAccessor(&fileAccessor{})
	}
	if removeNetworkAccessor {
		f.removeAccessor(&networkAccessor{})
	}
	if removeMemAccessor {
		f.removeAccessor(&memAccessor{})
	}
	if removeThreadAccessor {
		f.removeAccessor(&threadAccessor{})
	}
}

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

package ps

import (
	"path/filepath"
	"sync"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/util/cmdline"
)

var (
	defaultMapper *Mapper
	defaultOnce   sync.Once
	captureMapper = NewCaptureMapper()
)

// DefaultMapper returns the process-wide mapper that resolves the process user and
// domain with the shared user resolver. The mapper is stateless, so it is safe for
// concurrent use and there is no need for the callers to hold their own instance.
func DefaultMapper() *Mapper {
	defaultOnce.Do(func() { defaultMapper = NewMapper(Users()) })
	return defaultMapper
}

// CaptureMapper returns the process-wide mapper for the events replayed from a capture file.
func CaptureMapper() *Mapper { return captureMapper }

// Mapper turns the raw events into the process state types that are
// understood by the snapshotter. The mapper is a pure function of the
// event parameters. They don't touch the snapshotter state, nor do they
// query the OS, with the only exception of the SID to account resolution
// which is backed by a cache. This keeps the snapshotter API independent of
// the event layout and the expensive enrichment steps out of the lock scope.
type Mapper struct {
	users *UserResolver
}

// NewMapper creates a new mapper that resolves the process
// user/domain from the SID by using the given user resolver.
func NewMapper(users *UserResolver) *Mapper {
	return &Mapper{users: users}
}

// NewCaptureMapper creates a mapper for the events replayed from a capture file.
// The SID can't be resolved on the machine where the capture is being analyzed,
// since the account may not exist there, so the user name and domain are taken
// from the event parameters stored in the capture.
func NewCaptureMapper() *Mapper {
	return &Mapper{}
}

// Proc maps the process state from the process creation or rundown event.
// The internal variants of these events carry only a subset of attributes (the
// executable path and token properties) that are meant to enrich the process
// state originating from the NT kernel logger events. The state built from them
// is not flagged as created from the system logger.
func (m *Mapper) Proc(e *event.Event) *pstypes.PS {
	pid := e.Params.GetPid()
	ppid := e.Params.GetPpid()

	if e.IsCreateProcessInternal() || e.IsProcessRundownInternal() {
		exe := e.GetParamAsString(params.Exe)
		return &pstypes.PS{
			PID:                 pid,
			Ppid:                ppid,
			Exe:                 exe,
			Name:                filepath.Base(exe),
			SeqNum:              e.Params.GetUint64ByName(params.ProcessSequenceNumber),
			ParentSeqNum:        e.Params.GetUint64ByName(params.ParentProcessSequenceNumber),
			StartTime:           e.Params.GetTimeByName(params.StartTime),
			TokenIntegrityLevel: e.GetParamAsString(params.ProcessTokenIntegrityLevel),
			TokenElevationType:  e.GetParamAsString(params.ProcessTokenElevationType),
			IsTokenElevated:     e.Params.GetBoolByName(params.ProcessTokenIsElevated),
			Threads:             make(map[uint32]pstypes.Thread),
			Modules:             make([]pstypes.Module, 0),
			Handles:             make([]htypes.Handle, 0),
			Mmaps:               make([]pstypes.Mmap, 0),
		}
	}

	cmndline := e.GetParamAsString(params.Cmdline)
	flags := e.Params.GetUint32ByName(params.ProcessFlags)

	proc := &pstypes.PS{
		PID:                       pid,
		Ppid:                      ppid,
		Name:                      e.GetParamAsString(params.ProcessName),
		Cmdline:                   cmndline,
		Exe:                       e.GetParamAsString(params.Exe),
		Args:                      cmdline.Split(cmndline),
		SessionID:                 e.Params.GetUint32ByName(params.SessionID),
		StartTime:                 e.Params.GetTimeByName(params.StartTime),
		IsWOW64:                   flags&params.PsWOW64 != 0,
		IsPackaged:                flags&params.PsPackaged != 0,
		IsProtected:               flags&params.PsProtected != 0,
		IsCreatedFromSystemLogger: true,
		Threads:                   make(map[uint32]pstypes.Thread),
		Modules:                   make([]pstypes.Module, 0),
		Handles:                   make([]htypes.Handle, 0),
		Mmaps:                     make([]pstypes.Mmap, 0),
	}

	if sid := e.Params.GetSID(); sid != nil {
		proc.SID = sid.String()
	}

	if m.users != nil {
		proc.Domain, proc.Username = splitDomainUser(m.users.GetUser(proc.SID))
	} else {
		proc.Username = e.GetParamAsString(params.Username)
		proc.Domain = e.GetParamAsString(params.Domain)
	}

	return proc
}

// Thread maps the thread state from the thread creation or rundown event.
func (*Mapper) Thread(e *event.Event) pstypes.Thread {
	return pstypes.Thread{
		Pid:          e.Params.GetPid(),
		Tid:          e.Params.GetTid(),
		UstackBase:   e.Params.GetAddressByName(params.UstackBase),
		UstackLimit:  e.Params.GetAddressByName(params.UstackLimit),
		KstackBase:   e.Params.GetAddressByName(params.KstackBase),
		KstackLimit:  e.Params.GetAddressByName(params.KstackLimit),
		IOPrio:       e.Params.GetUint8ByName(params.IOPrio),
		BasePrio:     e.Params.GetUint8ByName(params.BasePrio),
		PagePrio:     e.Params.GetUint8ByName(params.PagePrio),
		StartAddress: e.Params.GetAddressByName(params.StartAddress),
	}
}

// Module maps the module state from the module load or rundown event. It also
// returns the identifier of the process the module is loaded into. The module
// rundown events report the zero process identifier for the modules loaded
// in the System process, so it is translated into its actual identifier.
func (*Mapper) Module(e *event.Event) (uint32, pstypes.Module) {
	pid := e.Params.GetPid()
	if pid == 0 && e.IsModuleRundown() {
		pid = SystemPID
	}
	return pid, pstypes.Module{
		Size:               e.Params.GetUint64ByName(params.ModuleSize),
		Checksum:           e.Params.GetUint32ByName(params.ModuleCheckSum),
		TimedateStamp:      e.Params.GetUint32ByName(params.ModuleTimeDateStamp),
		Name:               e.GetParamAsString(params.ModulePath),
		BaseAddress:        e.Params.GetAddressByName(params.ModuleBase),
		DefaultBaseAddress: e.Params.GetAddressByName(params.ModuleDefaultBase),
		SignatureLevel:     e.Params.GetUint32ByName(params.ModuleSignatureLevel),
		SignatureType:      e.Params.GetUint32ByName(params.ModuleSignatureType),
	}
}

// Mmap creates the memory mapping state from the map view of section event. It also
// returns the identifier of the process in whose address space the view is mapped.
func (*Mapper) Mmap(e *event.Event) (uint32, pstypes.Mmap) {
	return e.PID, pstypes.Mmap{
		File:        e.GetParamAsString(params.FilePath),
		BaseAddress: e.Params.GetAddressByName(params.FileViewBase),
		Size:        e.Params.GetUint64ByName(params.FileViewSize),
		Protection:  e.Params.GetUint32ByName(params.MemProtect),
		Type:        e.GetParamAsString(params.FileViewSectionType),
	}
}

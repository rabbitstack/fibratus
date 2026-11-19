//go:build !integration

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
	"sync/atomic"
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// system account SID (S-1-5-18) in the WBEM layout
var systemSID = []byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}

func processEvent(typ event.Type) *event.Event {
	return &event.Event{
		Type: typ,
		Params: event.ParamsOf(
			event.NewParam(params.ProcessID, params.PID, params.U32(uint32(1024))),
			event.NewParam(params.ProcessParentID, params.PID, params.U32(uint32(444))),
			event.NewParam(params.ProcessName, params.String, params.Str("svchost.exe")),
			event.NewParam(params.Cmdline, params.String, params.Str(`C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s NcbService`)),
			event.NewParam(params.Exe, params.String, params.Str(`C:\Windows\System32\svchost.exe`)),
			event.NewParam(params.UserSID, params.WbemSID, params.Bin(systemSID)),
			event.NewParam(params.SessionID, params.Uint32, params.U32(uint32(2))),
			event.NewParam(params.ProcessFlags, params.Flags32, params.U32(uint32(params.PsWOW64|params.PsProtected))),
			event.NewParam(params.StartTime, params.Time, params.Timestamp(time.Unix(1700000000, 42))),
		),
	}
}

func TestMapperSingletons(t *testing.T) {
	// the accessors hand out the same stateless instance every time
	assert.Same(t, DefaultMapper(), DefaultMapper())
	assert.Same(t, CaptureMapper(), CaptureMapper())
	assert.NotSame(t, DefaultMapper(), CaptureMapper())

	// the capture mapper doesn't resolve the SID, but takes the
	// account from the event parameters instead
	evt := processEvent(event.CreateProcess)
	evt.Params.Append(params.Username, params.String, params.Str("nedo"))
	evt.Params.Append(params.Domain, params.String, params.Str("WORKGROUP"))
	proc := CaptureMapper().Proc(evt)
	assert.Equal(t, "nedo", proc.Username)
	assert.Equal(t, "WORKGROUP", proc.Domain)
}

func TestMapProcess(t *testing.T) {
	m := NewMapper(NewUserResolver())

	for _, typ := range []event.Type{event.CreateProcess, event.ProcessRundown} {
		proc := m.Proc(processEvent(typ))

		require.NotNil(t, proc)
		assert.Equal(t, uint32(1024), proc.PID)
		assert.Equal(t, uint32(444), proc.Ppid)
		assert.Equal(t, "svchost.exe", proc.Name)
		assert.Equal(t, `C:\Windows\System32\svchost.exe`, proc.Exe)
		assert.Equal(t, `C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s NcbService`, proc.Cmdline)
		assert.Len(t, proc.Args, 6)
		assert.Equal(t, "S-1-5-18", proc.SID)
		assert.Equal(t, "SYSTEM", proc.Username)
		assert.Equal(t, "NT AUTHORITY", proc.Domain)
		assert.Equal(t, uint32(2), proc.SessionID)
		assert.Equal(t, int64(1700000000*1e9+42), proc.StartTime.UnixNano())
		assert.True(t, proc.IsWOW64)
		assert.True(t, proc.IsProtected)
		assert.False(t, proc.IsPackaged)
		assert.True(t, proc.IsCreatedFromSystemLogger)
		assert.NotNil(t, proc.Threads)
		assert.NotNil(t, proc.Modules)
		assert.NotNil(t, proc.Mmaps)
		assert.NotNil(t, proc.Handles)
		assert.Nil(t, proc.Parent)
	}
}

func TestMapProcessWithoutSID(t *testing.T) {
	var calls atomic.Int32
	m := NewMapper(NewUserResolver())

	evt := &event.Event{
		Type: event.CreateProcess,
		Params: event.ParamsOf(
			event.NewParam(params.ProcessID, params.PID, params.U32(uint32(1023))),
			event.NewParam(params.Cmdline, params.String, params.Str(`C:\Windows\system32\svchost.exe -k RPCSS`)),
		),
	}

	proc := m.Proc(evt)
	require.NotNil(t, proc)
	assert.Equal(t, uint32(1023), proc.PID)
	assert.Empty(t, proc.SID)
	assert.Empty(t, proc.Username)
	assert.Empty(t, proc.Domain)
	assert.Equal(t, int32(0), calls.Load())
}

func TestMapProcessInternal(t *testing.T) {
	m := NewMapper(NewUserResolver())

	for _, typ := range []event.Type{event.CreateProcessInternal, event.ProcessRundownInternal} {
		evt := &event.Event{
			Type: typ,
			Params: event.ParamsOf(
				event.NewParam(params.ProcessID, params.PID, params.U32(uint32(1024))),
				event.NewParam(params.ProcessParentID, params.PID, params.U32(uint32(444))),
				event.NewParam(params.Exe, params.String, params.Str(`C:\Windows\System32\svchost.exe`)),
				event.NewParam(params.ProcessTokenIntegrityLevel, params.String, params.Str("HIGH")),
				event.NewParam(params.ProcessTokenIsElevated, params.Bool, params.Boolean(true)),
				event.NewParam(params.ProcessTokenElevationType, params.String, params.Str("FULL")),
			),
		}

		proc := m.Proc(evt)
		require.NotNil(t, proc)
		assert.Equal(t, uint32(1024), proc.PID)
		assert.Equal(t, uint32(444), proc.Ppid)
		assert.Equal(t, `C:\Windows\System32\svchost.exe`, proc.Exe)
		assert.Equal(t, "svchost.exe", proc.Name)
		assert.Equal(t, "HIGH", proc.TokenIntegrityLevel)
		assert.Equal(t, "FULL", proc.TokenElevationType)
		assert.True(t, proc.IsTokenElevated)
		// the state derived from internal events must not
		// masquerade as the one built from the system logger
		assert.False(t, proc.IsCreatedFromSystemLogger)
	}
}

func TestMapProcessFromCapture(t *testing.T) {
	m := NewCaptureMapper()

	evt := processEvent(event.CreateProcess)
	evt.Params.Append(params.Username, params.String, params.Str("admin"))
	evt.Params.Append(params.Domain, params.String, params.Str("WORKGROUP"))

	proc := m.Proc(evt)
	require.NotNil(t, proc)
	// user and domain are restored from the captured parameters
	assert.Equal(t, "S-1-5-18", proc.SID)
	assert.Equal(t, "admin", proc.Username)
	assert.Equal(t, "WORKGROUP", proc.Domain)
}

func TestMapThread(t *testing.T) {
	m := NewMapper(nil)

	evt := &event.Event{
		Type: event.CreateThread,
		Params: event.ParamsOf(
			event.NewParam(params.ProcessID, params.PID, params.U32(uint32(760))),
			event.NewParam(params.ThreadID, params.TID, params.U32(uint32(3453))),
			event.NewParam(params.BasePrio, params.Uint8, params.U8(uint8(13))),
			event.NewParam(params.StartAddress, params.Address, params.U64(uint64(140729524944768))),
			event.NewParam(params.IOPrio, params.Uint8, params.U8(uint8(2))),
			event.NewParam(params.KstackBase, params.Address, params.U64(uint64(18446677035730165760))),
			event.NewParam(params.KstackLimit, params.Address, params.U64(uint64(18446677035730137088))),
			event.NewParam(params.PagePrio, params.Uint8, params.U8(uint8(5))),
			event.NewParam(params.UstackBase, params.Address, params.U64(uint64(86376448))),
			event.NewParam(params.UstackLimit, params.Address, params.U64(uint64(86372352))),
		),
	}

	thread := m.Thread(evt)
	assert.Equal(t, uint32(760), thread.Pid)
	assert.Equal(t, uint32(3453), thread.Tid)
	assert.Equal(t, uint8(13), thread.BasePrio)
	assert.Equal(t, uint8(2), thread.IOPrio)
	assert.Equal(t, uint8(5), thread.PagePrio)
	assert.Equal(t, va.Address(140729524944768), thread.StartAddress)
	assert.Equal(t, va.Address(18446677035730165760), thread.KstackBase)
	assert.Equal(t, va.Address(18446677035730137088), thread.KstackLimit)
	assert.Equal(t, va.Address(86376448), thread.UstackBase)
	assert.Equal(t, va.Address(86372352), thread.UstackLimit)
}

func moduleEvent(typ event.Type, pid uint32) *event.Event {
	return &event.Event{
		Type: typ,
		Params: event.ParamsOf(
			event.NewParam(params.ProcessID, params.PID, params.U32(pid)),
			event.NewParam(params.ModulePath, params.String, params.Str(`C:\Windows\System32\kernel32.dll`)),
			event.NewParam(params.ModuleSize, params.Uint64, params.U64(uint64(0x1000))),
			event.NewParam(params.ModuleCheckSum, params.Uint32, params.U32(uint32(2323432))),
			event.NewParam(params.ModuleTimeDateStamp, params.Uint32, params.U32(uint32(1600000000))),
			event.NewParam(params.ModuleBase, params.Address, params.U64(uint64(0x7ffb313833a3))),
			event.NewParam(params.ModuleDefaultBase, params.Address, params.U64(uint64(0x7ffb31380000))),
			event.NewParam(params.ModuleSignatureType, params.Uint32, params.U32(uint32(1))),
			event.NewParam(params.ModuleSignatureLevel, params.Uint32, params.U32(uint32(4))),
		),
	}
}

func TestMapModule(t *testing.T) {
	m := NewMapper(nil)

	pid, mod := m.Module(moduleEvent(event.LoadModule, 1023))
	assert.Equal(t, uint32(1023), pid)
	assert.Equal(t, `C:\Windows\System32\kernel32.dll`, mod.Name)
	assert.Equal(t, uint64(0x1000), mod.Size)
	assert.Equal(t, uint32(2323432), mod.Checksum)
	assert.Equal(t, uint32(1600000000), mod.TimedateStamp)
	assert.Equal(t, va.Address(0x7ffb313833a3), mod.BaseAddress)
	assert.Equal(t, va.Address(0x7ffb31380000), mod.DefaultBaseAddress)
	assert.Equal(t, uint32(1), mod.SignatureType)
	assert.Equal(t, uint32(4), mod.SignatureLevel)
}

func TestMapModuleSystemProcessRundown(t *testing.T) {
	m := NewMapper(nil)

	// the rundown events report modules of the System process with the zero pid
	pid, _ := m.Module(moduleEvent(event.ModuleRundown, 0))
	assert.Equal(t, SystemPID, pid)

	// but only the rundown events get such treatment
	pid, _ = m.Module(moduleEvent(event.LoadModule, 0))
	assert.Equal(t, uint32(0), pid)

	pid, _ = m.Module(moduleEvent(event.ModuleRundown, 1023))
	assert.Equal(t, uint32(1023), pid)
}

func TestMapMmap(t *testing.T) {
	m := NewMapper(nil)

	evt := &event.Event{
		PID:  10233,
		Type: event.MapViewOfSection,
		Params: event.ParamsOf(
			event.NewParam(params.FilePath, params.String, params.Str(`C:\Windows\System32\kernel32.dll`)),
			event.NewParam(params.FileViewBase, params.Address, params.U64(uint64(0xffff23433))),
			event.NewParam(params.FileViewSize, params.Uint64, params.U64(uint64(3098))),
			event.NewParam(params.MemProtect, params.Uint32, params.U32(uint32(0x20))),
			event.NewParam(params.FileViewSectionType, params.String, params.Str("IMAGE")),
		),
	}

	pid, mmap := m.Mmap(evt)
	assert.Equal(t, uint32(10233), pid)
	assert.Equal(t, `C:\Windows\System32\kernel32.dll`, mmap.File)
	assert.Equal(t, va.Address(0xffff23433), mmap.BaseAddress)
	assert.Equal(t, uint64(3098), mmap.Size)
	assert.Equal(t, uint32(0x20), mmap.Protection)
	assert.Equal(t, "IMAGE", mmap.Type)
}

/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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

package symbolize

import (
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/pe"
	"github.com/rabbitstack/fibratus/pkg/ps"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// MockResolver for unit testing
type MockResolver struct {
	mock.Mock
}

// Initialize method...
func (r *MockResolver) Initialize(proc windows.Handle, opts uint32) error {
	called := r.Called(proc, opts)
	return called.Error(0)
}

// GetModuleName method...
func (r *MockResolver) GetModuleName(proc windows.Handle, addr va.Address) string {
	called := r.Called(proc, addr)
	return called.String(0)
}

// GetSymbolNameAndOffset method...
func (r *MockResolver) GetSymbolNameAndOffset(proc windows.Handle, addr va.Address) (string, uint64) {
	called := r.Called(proc, addr)
	return called.String(0), uint64(called.Int(1))
}

// LoadModule method...
func (r *MockResolver) LoadModule(proc windows.Handle, module string, addr va.Address) error {
	called := r.Called(proc, module, addr)
	return called.Error(0)
}

// UnloadModule method...
func (r *MockResolver) UnloadModule(proc windows.Handle, addr va.Address) {
	r.Called(proc, addr)
}

// Cleanup method...
func (r *MockResolver) Cleanup(proc windows.Handle) {
	r.Called(proc)
}

func TestLoadKernelModuleSymbolTables(t *testing.T) {
	r := new(MockResolver)
	c := &config.Config{SymbolizeKernelAddresses: true}

	psnap := new(ps.SnapshotterMock)

	opts := uint32(sys.SymUndname | sys.SymCaseInsensitive | sys.SymAutoPublics)
	r.On("Initialize", windows.CurrentProcess(), opts).Return(nil)
	r.On("LoadModule", windows.CurrentProcess(), mock.Anything, mock.Anything).Return(nil)
	r.On("UnloadModule", mock.Anything, mock.Anything)

	s := NewSymbolizer(r, psnap, c, false)
	require.NotNil(t, s)
	defer s.Close()

	r.AssertNumberOfCalls(t, "Initialize", 1)
	r.AssertNumberOfCalls(t, "LoadModule", len(sys.EnumDevices()))
}

func TestProcessCallstackPeExports(t *testing.T) {
	r := new(MockResolver)
	c := &config.Config{}
	log.SetLevel(log.DebugLevel)

	psnap := new(ps.SnapshotterMock)

	r.On("UnloadModule", mock.Anything, mock.Anything)
	opts := uint32(sys.SymUndname | sys.SymCaseInsensitive | sys.SymAutoPublics | sys.SymOmapFindNearest | sys.SymDeferredLoads)
	r.On("Initialize", mock.Anything, opts).Return(nil)
	r.On("Cleanup", mock.Anything)

	r.On("GetModuleName", mock.Anything, mock.Anything).Return("?").Once()
	r.On("GetSymbolNameAndOffset", mock.Anything, mock.Anything).Return("?", 0).Once()
	r.On("GetSymbolNameAndOffset", mock.Anything, mock.Anything).Return("CreateProcessW", 0x54).Once()

	psnap.On("FindModule", mock.Anything).Return(false, nil).Once()

	s := NewSymbolizer(r, psnap, c, false)
	require.NotNil(t, s)
	defer s.Close()

	proc := &pstypes.PS{
		Name:      "notepad.exe",
		PID:       23234,
		Ppid:      2434,
		Exe:       `C:\Windows\notepad.exe`,
		Cmdline:   `C:\Windows\notepad.exe`,
		SID:       "S-1-1-18",
		Cwd:       `C:\Windows\`,
		SessionID: 1,
		Threads: map[uint32]pstypes.Thread{
			3453: {Tid: 3453, StartAddress: va.Address(140729524944768), IOPrio: 2, PagePrio: 5, KstackBase: va.Address(18446677035730165760), KstackLimit: va.Address(18446677035730137088), UstackLimit: va.Address(86376448), UstackBase: va.Address(86372352)},
			3455: {Tid: 3455, StartAddress: va.Address(140729524944768), IOPrio: 3, PagePrio: 5, KstackBase: va.Address(18446677035730165760), KstackLimit: va.Address(18446677035730137088), UstackLimit: va.Address(86376448), UstackBase: va.Address(86372352)},
		},
		Envs: map[string]string{"ProgramData": "C:\\ProgramData", "COMPUTRENAME": "archrabbit"},
		Modules: []pstypes.Module{
			{Name: "C:\\Windows\\System32\\ntdll.dll", Size: 32358, Checksum: 23123343, BaseAddress: va.Address(0x7ffb313833a3), DefaultBaseAddress: va.Address(0x7ffb313833a3)},
			{Name: "C:\\Windows\\System32\\kernel32.dll", Size: 12354, Checksum: 23123343, BaseAddress: va.Address(0x7ffb5c1d0126), DefaultBaseAddress: va.Address(0x7ffb5c1d0126)},
			{Name: "C:\\Windows\\System32\\user32.dll", Size: 212354, Checksum: 33123343, BaseAddress: va.Address(0x7ffb5d8e11c4), DefaultBaseAddress: va.Address(0x7ffb5d8e11c4)},
		},
	}

	e := &event.Event{
		Type:        event.CreateFile,
		Tid:         2484,
		PID:         uint32(os.Getpid()),
		CPU:         1,
		Seq:         2,
		Name:        "CreateFile",
		Timestamp:   time.Now(),
		Category:    event.File,
		Host:        "archrabbit",
		Description: "Creates or opens a new file, directory, I/O device, pipe, console",
		Params: event.Params{
			params.FileObject:    {Name: params.FileObject, Type: params.Uint64, Value: uint64(12456738026482168384)},
			params.FilePath:      {Name: params.FilePath, Type: params.UnicodeString, Value: "C:\\Windows\\system32\\mimi.dll"},
			params.FileType:      {Name: params.FileType, Type: params.AnsiString, Value: "file"},
			params.FileOperation: {Name: params.FileOperation, Type: params.Enum, Value: uint32(2), Enum: fs.FileCreateDispositions},
			params.Callstack:     {Name: params.Callstack, Type: params.Slice, Value: []va.Address{0x7ffb5c1d0396, 0x7ffb5d8e61f4, 0x7ffb3138592e, 0x7ffb313853b2, 0x2638e59e0a5}},
		},
		PS: proc,
	}

	parsePeFile = func(name string, option ...pe.Option) (*pe.PE, error) {
		exports := map[uint32]string{
			8192:  "RtlSetSearchPathMode",
			9344:  "RtlCreateQueryDebugBuffer",
			20352: "LoadKeyboardLayoutW",
		}
		px := &pe.PE{
			Exports: exports,
		}
		return px, nil
	}

	_, err := s.ProcessEvent(e)
	require.NoError(t, err)

	assert.Len(t, e.Callstack, 5)
	assert.Len(t, e.Callstack.Symbols(), 5)
	assert.Len(t, e.Callstack.Modules(), 5)

	assert.Equal(t, "unbacked!?", e.Callstack.Symbols()[0])
	assert.Equal(t, "ntdll.dll!RtlSetSearchPathMode", e.Callstack.Symbols()[1])
	assert.Equal(t, "ntdll.dll!RtlCreateQueryDebugBuffer", e.Callstack.Symbols()[2])
	assert.Equal(t, "user32.dll!LoadKeyboardLayoutW", e.Callstack.Symbols()[3])
	assert.Equal(t, "kernel32.dll!?", e.Callstack.Symbols()[4]) // unexported symbol

	assert.Equal(t, "kernel32.dll|user32.dll|ntdll.dll|unbacked", e.Callstack.Summary())
	assert.True(t, e.Callstack.ContainsUnbacked())

	// check internal state
	assert.Len(t, s.mods, 1)
	assert.Len(t, s.mods[e.PID], 3)

	// should have populated the symbols cache
	assert.Len(t, s.symbols, 1)
	assert.Equal(t, syminfo{module: "unbacked", symbol: "?"}, s.symbols[e.PID][0x2638e59e0a5])

	e3 := &event.Event{
		Type:      event.UnloadImage,
		Tid:       2484,
		PID:       uint32(os.Getpid()),
		CPU:       1,
		Seq:       2,
		Name:      "UnloadImage",
		Timestamp: time.Now(),
		Category:  event.Image,
		Params: event.Params{
			params.ImageBase: {Name: params.ImageBase, Type: params.Address, Value: uint64(0x7ffb5d8e11c4)},
			params.FilePath:  {Name: params.FilePath, Type: params.UnicodeString, Value: `C:\Windows\System32\user32.dll`},
		},
		PS: proc,
	}

	// dll is unloaded, the number of modules should decrement
	_, err = s.ProcessEvent(e3)
	require.NoError(t, err)
	assert.Len(t, s.mods[e.PID], 2)
}

func TestProcessCallstack(t *testing.T) {
	r := new(MockResolver)
	c := &config.Config{}

	psnap := new(ps.SnapshotterMock)

	opts := uint32(sys.SymUndname | sys.SymCaseInsensitive | sys.SymAutoPublics | sys.SymOmapFindNearest | sys.SymDeferredLoads)
	r.On("Initialize", mock.Anything, opts).Return(nil)
	r.On("LoadModule", windows.CurrentProcess(), mock.Anything).Return(nil)

	r.On("GetModuleName", mock.Anything, mock.Anything).Return("C:\\WINDOWS\\System32\\KERNEL32.DLL").Once()
	r.On("GetModuleName", mock.Anything, mock.Anything).Return("C:\\WINDOWS\\System32\\KERNELBASE.dll").Once()
	r.On("GetModuleName", mock.Anything, mock.Anything).Return("C:\\WINDOWS\\System32\\ntdll.dll").Times(3)

	r.On("GetSymbolNameAndOffset", mock.Anything, mock.Anything).Return("CreateProcessW", 0x54).Once()
	r.On("GetSymbolNameAndOffset", mock.Anything, mock.Anything).Return("CreateProcessW", 0x66).Once()
	r.On("GetSymbolNameAndOffset", mock.Anything, mock.Anything).Return("NtCreateProcess", 0x3a2).Once()
	r.On("GetSymbolNameAndOffset", mock.Anything, mock.Anything).Return("NtCreateProcessEx", 0x3a2).Times(2)

	r.On("Cleanup", mock.Anything)

	s := NewSymbolizer(r, psnap, c, false)
	require.NotNil(t, s)

	proc := &pstypes.PS{
		Name:      "notepad.exe",
		PID:       23234,
		Ppid:      2434,
		Exe:       `C:\Windows\notepad.exe`,
		Cmdline:   `C:\Windows\notepad.exe`,
		SID:       "S-1-1-18",
		Cwd:       `C:\Windows\`,
		SessionID: 1,
		Threads: map[uint32]pstypes.Thread{
			3453: {Tid: 3453, StartAddress: va.Address(140729524944768), IOPrio: 2, PagePrio: 5, KstackBase: va.Address(18446677035730165760), KstackLimit: va.Address(18446677035730137088), UstackLimit: va.Address(86376448), UstackBase: va.Address(86372352)},
			3455: {Tid: 3455, StartAddress: va.Address(140729524944768), IOPrio: 3, PagePrio: 5, KstackBase: va.Address(18446677035730165760), KstackLimit: va.Address(18446677035730137088), UstackLimit: va.Address(86376448), UstackBase: va.Address(86372352)},
		},
		Envs: map[string]string{"ProgramData": "C:\\ProgramData", "COMPUTRENAME": "archrabbit"},
	}
	e := &event.Event{
		Type:      event.CreateProcess,
		Tid:       2484,
		PID:       2232,
		CPU:       1,
		Seq:       2,
		Name:      "CreatedProcess",
		Timestamp: time.Now(),
		Category:  event.Process,
		Host:      "archrabbit",
		Params: event.Params{
			params.ProcessParentID: {Name: params.ProcessParentID, Type: params.PID, Value: (uint32(os.Getpid()))},
			params.Callstack:       {Name: params.Callstack, Type: params.Slice, Value: []va.Address{0x7ffb5c1d0396, 0x7ffb5d8e61f4, 0x7ffb3138592e, 0x7ffb313853b2, 0x2638e59e0a5}},
		},
		PS: proc,
	}

	_, err := s.ProcessEvent(e)
	require.NoError(t, err)
	assert.Equal(t, 1, s.procsSize())
	assert.Equal(t, "0x7ffb5c1d0396 C:\\WINDOWS\\System32\\ntdll.dll!NtCreateProcessEx+0x3a2|0x7ffb5d8e61f4 C:\\WINDOWS\\System32\\ntdll.dll!NtCreateProcessEx+0x3a2|0x7ffb3138592e C:\\WINDOWS\\System32\\ntdll.dll!NtCreateProcess+0x3a2|0x7ffb313853b2 C:\\WINDOWS\\System32\\KERNELBASE.dll!CreateProcessW+0x66|0x2638e59e0a5 C:\\WINDOWS\\System32\\KERNEL32.DLL!CreateProcessW+0x54", e.Callstack.String())

	e1 := &event.Event{
		Type:      event.TerminateProcess,
		Tid:       2484,
		PID:       12345,
		CPU:       1,
		Seq:       3,
		Name:      "TerminateProcess",
		Timestamp: time.Now(),
		Category:  event.Process,
		Host:      "archrabbit",
		Params: event.Params{
			params.ProcessID: {Name: params.ProcessID, Type: params.PID, Value: uint32(os.Getpid())},
		},
		PS: proc,
	}
	_, err = s.ProcessEvent(e1)
	require.NoError(t, err)

	r.AssertNumberOfCalls(t, "Cleanup", 1)
	assert.Equal(t, 0, s.procsSize())
}

func TestSymbolizeEventParamAddress(t *testing.T) {
	r := new(MockResolver)
	c := &config.Config{}

	psnap := new(ps.SnapshotterMock)

	opts := uint32(sys.SymUndname | sys.SymCaseInsensitive | sys.SymAutoPublics | sys.SymOmapFindNearest | sys.SymDeferredLoads)
	r.On("Initialize", mock.Anything, opts).Return(nil)
	r.On("LoadModule", windows.CurrentProcess(), mock.Anything).Return(nil)

	r.On("GetModuleName", mock.Anything, mock.Anything).Return("C:\\WINDOWS\\System32\\KERNEL32.DLL").Once()
	r.On("GetModuleName", mock.Anything, mock.Anything).Return("C:\\WINDOWS\\System32\\KERNELBASE.dll").Once()
	r.On("GetModuleName", mock.Anything, mock.Anything).Return("C:\\WINDOWS\\System32\\ntdll.dll").Times(3)

	r.On("GetSymbolNameAndOffset", mock.Anything, mock.Anything).Return("CreateProcessW", 0x54).Times(2)
	r.On("GetSymbolNameAndOffset", mock.Anything, mock.Anything).Return("CreateProcessW", 0x66).Once()
	r.On("GetSymbolNameAndOffset", mock.Anything, mock.Anything).Return("NtCreateProcess", 0x3a2).Once()
	r.On("GetSymbolNameAndOffset", mock.Anything, mock.Anything).Return("NtCreateProcessEx", 0x3a2).Times(2)

	r.On("Cleanup", mock.Anything)

	s := NewSymbolizer(r, psnap, c, false)
	require.NotNil(t, s)

	parsePeFile = func(name string, option ...pe.Option) (*pe.PE, error) {
		exports := map[uint32]string{
			8192:  "RtlSetSearchPathMode",
			9344:  "CreateProcessW",
			20352: "LoadKeyboardLayoutW",
		}
		px := &pe.PE{
			Exports: exports,
		}
		return px, nil
	}

	proc := &pstypes.PS{
		Name:      "notepad.exe",
		PID:       23234,
		Ppid:      2434,
		Exe:       `C:\Windows\notepad.exe`,
		Cmdline:   `C:\Windows\notepad.exe`,
		SID:       "S-1-1-18",
		Cwd:       `C:\Windows\`,
		SessionID: 1,
		Threads: map[uint32]pstypes.Thread{
			3453: {Tid: 3453, StartAddress: va.Address(140729524944768), IOPrio: 2, PagePrio: 5, KstackBase: va.Address(18446677035730165760), KstackLimit: va.Address(18446677035730137088), UstackLimit: va.Address(86376448), UstackBase: va.Address(86372352)},
			3455: {Tid: 3455, StartAddress: va.Address(140729524944768), IOPrio: 3, PagePrio: 5, KstackBase: va.Address(18446677035730165760), KstackLimit: va.Address(18446677035730137088), UstackLimit: va.Address(86376448), UstackBase: va.Address(86372352)},
		},
		Envs: map[string]string{"ProgramData": "C:\\ProgramData", "COMPUTRENAME": "archrabbit"},
		Modules: []pstypes.Module{
			{Name: "C:\\Windows\\System32\\ntdll.dll", Size: 32358, Checksum: 23123343, BaseAddress: va.Address(0x7ffb313833a3), DefaultBaseAddress: va.Address(0x7ffb313833a3)},
			{Name: "C:\\Windows\\System32\\kernel32.dll", Size: 12354, Checksum: 23123343, BaseAddress: va.Address(0x7ffb5c1d0126), DefaultBaseAddress: va.Address(0x7ffb5c1d0126)},
			{Name: "C:\\Windows\\System32\\user32.dll", Size: 212354, Checksum: 33123343, BaseAddress: va.Address(0x7ffb5d8e11c4), DefaultBaseAddress: va.Address(0x7ffb5d8e11c4)},
		},
	}
	e := &event.Event{
		Type:      event.CreateThread,
		Tid:       2484,
		PID:       uint32(os.Getpid()),
		CPU:       1,
		Seq:       2,
		Name:      "CreateThread",
		Timestamp: time.Now(),
		Category:  event.Thread,
		Host:      "archrabbit",
		Params: event.Params{
			params.Callstack:    {Name: params.Callstack, Type: params.Slice, Value: []va.Address{0x7ffb5c1d0396, 0x7ffb5d8e61f4, 0x7ffb3138592e, 0x7ffb313853b2, 0x2638e59e0a5}},
			params.StartAddress: {Name: params.StartAddress, Type: params.Address, Value: uint64(0x7ffb3138592e)},
			params.ProcessID:    {Name: params.ProcessID, Type: params.PID, Value: uint32(os.Getpid())},
		},
		PS: proc,
	}

	_, err := s.ProcessEvent(e)
	require.NoError(t, err)

	assert.Equal(t, "CreateProcessW", e.GetParamAsString(params.StartAddressSymbol))
	assert.Equal(t, "C:\\Windows\\System32\\ntdll.dll", e.GetParamAsString(params.StartAddressModule))

	e1 := &event.Event{
		Type:      event.SubmitThreadpoolCallback,
		Tid:       2484,
		PID:       uint32(os.Getpid()),
		CPU:       1,
		Seq:       2,
		Name:      "SubmitThreadpoolCallback",
		Timestamp: time.Now(),
		Category:  event.Threadpool,
		Host:      "archrabbit",
		Params: event.Params{
			params.Callstack:          {Name: params.Callstack, Type: params.Slice, Value: []va.Address{0x7ffb5c1d0396}},
			params.ThreadpoolCallback: {Name: params.ThreadpoolCallback, Type: params.Address, Value: uint64(0x7ffb3138592e)},
			params.ThreadpoolContext:  {Name: params.ThreadpoolContext, Type: params.Address, Value: uint64(0)},
		},
		PS: proc,
	}

	_, err = s.ProcessEvent(e1)
	require.NoError(t, err)

	assert.Equal(t, "CreateProcessW", e1.GetParamAsString(params.ThreadpoolCallbackSymbol))
	assert.Equal(t, "C:\\Windows\\System32\\ntdll.dll", e1.GetParamAsString(params.ThreadpoolCallbackModule))
}

func init() {
	procTTL = time.Second
}

func TestProcessCallstackProcsTTL(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	r := new(MockResolver)
	c := &config.Config{}

	psnap := new(ps.SnapshotterMock)

	opts := uint32(sys.SymUndname | sys.SymCaseInsensitive | sys.SymAutoPublics | sys.SymOmapFindNearest | sys.SymDeferredLoads)
	r.On("Initialize", mock.Anything, opts).Return(nil)
	r.On("LoadModule", windows.CurrentProcess(), mock.Anything).Return(nil)
	r.On("GetModuleName", mock.Anything, mock.Anything).Return("C:\\WINDOWS\\System32\\KERNEL32.DLL")
	r.On("GetSymbolNameAndOffset", mock.Anything, mock.Anything).Return("CreateProcessW", 0x54)
	r.On("Cleanup", mock.Anything)

	s := NewSymbolizer(r, psnap, c, false)
	require.NotNil(t, s)
	defer s.Close()

	n := 10
	for n > 0 {
		e := &event.Event{
			Type:      event.CreateProcess,
			Tid:       2484,
			PID:       1232,
			CPU:       1,
			Seq:       2,
			Name:      "CreatedProcess",
			Timestamp: time.Now().Add(time.Millisecond * time.Duration(n)),
			Category:  event.Process,
			Host:      "archrabbit",
			Params: event.Params{
				params.ProcessParentID: {Name: params.ProcessParentID, Type: params.PID, Value: (uint32(os.Getpid()))},
				params.Callstack:       {Name: params.Callstack, Type: params.Slice, Value: []va.Address{0x7ffb5c1d0396, 0x7ffb5d8e61f4, 0x7ffb3138592e, 0x7ffb313853b2, 0x2638e59e0a5}},
			},
		}
		_, _ = s.ProcessEvent(e)
		n--
		time.Sleep(time.Millisecond * time.Duration(rand.Intn(15)*n))
	}
	// process should be present
	assert.Equal(t, 1, s.procsSize())

	time.Sleep(time.Millisecond * 2250)

	// evicted
	r.AssertNumberOfCalls(t, "Cleanup", 1)
	assert.Equal(t, 0, s.procsSize())
}

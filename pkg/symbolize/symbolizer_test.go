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
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"math/rand"
	"os"
	"testing"
	"time"
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

	opts := uint32(sys.SymUndname | sys.SymCaseInsensitive | sys.SymAutoPublics)
	r.On("Initialize", windows.CurrentProcess(), opts).Return(nil)
	r.On("LoadModule", windows.CurrentProcess(), mock.Anything, mock.Anything).Return(nil)
	r.On("UnloadModule", mock.Anything, mock.Anything)

	s := NewSymbolizer(r, c, false)
	require.NotNil(t, s)
	defer s.Close()

	r.AssertNumberOfCalls(t, "Initialize", 1)
	r.AssertNumberOfCalls(t, "LoadModule", len(sys.EnumDevices()))
}

func TestProcessCallstackFastMode(t *testing.T) {
	r := new(MockResolver)
	c := &config.Config{}

	r.On("UnloadModule", mock.Anything, mock.Anything)

	s := NewSymbolizer(r, c, false)
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
			3453: {Tid: 3453, Entrypoint: va.Address(140729524944768), IOPrio: 2, PagePrio: 5, KstackBase: va.Address(18446677035730165760), KstackLimit: va.Address(18446677035730137088), UstackLimit: va.Address(86376448), UstackBase: va.Address(86372352)},
			3455: {Tid: 3455, Entrypoint: va.Address(140729524944768), IOPrio: 3, PagePrio: 5, KstackBase: va.Address(18446677035730165760), KstackLimit: va.Address(18446677035730137088), UstackLimit: va.Address(86376448), UstackBase: va.Address(86372352)},
		},
		Envs: map[string]string{"ProgramData": "C:\\ProgramData", "COMPUTRENAME": "archrabbit"},
		Modules: []pstypes.Module{
			{Name: "ntdll.dll", Size: 32358, Checksum: 23123343, BaseAddress: va.Address(0x7ffb313833a3), DefaultBaseAddress: va.Address(0x7ffb313833a3)},
			{Name: "kernel32.dll", Size: 12354, Checksum: 23123343, BaseAddress: va.Address(0x7ffb5c1d0126), DefaultBaseAddress: va.Address(0x7ffb5c1d0126)},
			{Name: "user32.dll", Size: 212354, Checksum: 33123343, BaseAddress: va.Address(0x7ffb5d8e11c4), DefaultBaseAddress: va.Address(0x7ffb5d8e11c4)},
		},
	}
	e := &kevent.Kevent{
		Type:        ktypes.CreateFile,
		Tid:         2484,
		PID:         859,
		CPU:         1,
		Seq:         2,
		Name:        "CreateFile",
		Timestamp:   time.Now(),
		Category:    ktypes.File,
		Host:        "archrabbit",
		Description: "Creates or opens a new file, directory, I/O device, pipe, console",
		Kparams: kevent.Kparams{
			kparams.FileObject:    {Name: kparams.FileObject, Type: kparams.Uint64, Value: uint64(12456738026482168384)},
			kparams.FileName:      {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\user32.dll"},
			kparams.FileType:      {Name: kparams.FileType, Type: kparams.AnsiString, Value: "file"},
			kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.Enum, Value: uint32(1), Enum: fs.FileCreateDispositions},
			kparams.Callstack:     {Name: kparams.Callstack, Type: kparams.Slice, Value: []va.Address{0x7ffb5c1d0396, 0x7ffb5d8e61f4, 0x7ffb3138592e, 0x7ffb313853b2, 0x2638e59e0a5}},
		},
		PS: proc,
	}

	_, err := s.ProcessEvent(e)
	require.NoError(t, err)

	assert.Len(t, e.Callstack, 5)
	assert.Equal(t, "0x7ffb5c1d0396 kernel32.dll!?|0x7ffb5d8e61f4 user32.dll!?|0x7ffb3138592e ntdll.dll!?|0x7ffb313853b2 ntdll.dll!?|0x2638e59e0a5 unbacked!?", e.Callstack.String())
	assert.Equal(t, "kernel32.dll|user32.dll|ntdll.dll|unbacked", e.Callstack.Summary())
	assert.True(t, e.Callstack.ContainsUnbacked())
}

func TestProcessCallstackFullMode(t *testing.T) {
	r := new(MockResolver)
	c := &config.Config{}

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

	s := NewSymbolizer(r, c, false)
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
			3453: {Tid: 3453, Entrypoint: va.Address(140729524944768), IOPrio: 2, PagePrio: 5, KstackBase: va.Address(18446677035730165760), KstackLimit: va.Address(18446677035730137088), UstackLimit: va.Address(86376448), UstackBase: va.Address(86372352)},
			3455: {Tid: 3455, Entrypoint: va.Address(140729524944768), IOPrio: 3, PagePrio: 5, KstackBase: va.Address(18446677035730165760), KstackLimit: va.Address(18446677035730137088), UstackLimit: va.Address(86376448), UstackBase: va.Address(86372352)},
		},
		Envs: map[string]string{"ProgramData": "C:\\ProgramData", "COMPUTRENAME": "archrabbit"},
		Modules: []pstypes.Module{
			{Name: "ntdll.dll", Size: 32358, Checksum: 23123343, BaseAddress: va.Address(0x7ffb313833a3), DefaultBaseAddress: va.Address(0x7ffb313833a3)},
			{Name: "kernel32.dll", Size: 12354, Checksum: 23123343, BaseAddress: va.Address(0x7ffb5c1d0126), DefaultBaseAddress: va.Address(0x7ffb5c1d0126)},
			{Name: "user32.dll", Size: 212354, Checksum: 33123343, BaseAddress: va.Address(0x7ffb5d8e11c4), DefaultBaseAddress: va.Address(0x7ffb5d8e11c4)},
		},
	}
	e := &kevent.Kevent{
		Type:      ktypes.CreateProcess,
		Tid:       2484,
		PID:       uint32(os.Getpid()),
		CPU:       1,
		Seq:       2,
		Name:      "CreatedProcess",
		Timestamp: time.Now(),
		Category:  ktypes.Process,
		Host:      "archrabbit",
		Kparams: kevent.Kparams{
			kparams.Callstack: {Name: kparams.Callstack, Type: kparams.Slice, Value: []va.Address{0x7ffb5c1d0396, 0x7ffb5d8e61f4, 0x7ffb3138592e, 0x7ffb313853b2, 0x2638e59e0a5}},
		},
		PS: proc,
	}

	_, err := s.ProcessEvent(e)
	require.NoError(t, err)
	assert.Equal(t, 1, s.procsSize())
	assert.Equal(t, "0x7ffb5c1d0396 C:\\WINDOWS\\System32\\ntdll.dll!NtCreateProcessEx+0x3a2|0x7ffb5d8e61f4 C:\\WINDOWS\\System32\\ntdll.dll!NtCreateProcessEx+0x3a2|0x7ffb3138592e C:\\WINDOWS\\System32\\ntdll.dll!NtCreateProcess+0x3a2|0x7ffb313853b2 C:\\WINDOWS\\System32\\KERNELBASE.dll!CreateProcessW+0x66|0x2638e59e0a5 C:\\WINDOWS\\System32\\KERNEL32.DLL!CreateProcessW+0x54", e.Callstack.String())

	e1 := &kevent.Kevent{
		Type:      ktypes.TerminateProcess,
		Tid:       2484,
		PID:       12345,
		CPU:       1,
		Seq:       3,
		Name:      "TerminateProcess",
		Timestamp: time.Now(),
		Category:  ktypes.Process,
		Host:      "archrabbit",
		Kparams: kevent.Kparams{
			kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(os.Getpid())},
		},
		PS: proc,
	}
	_, err = s.ProcessEvent(e1)
	require.NoError(t, err)

	r.AssertNumberOfCalls(t, "Cleanup", 1)
	assert.Equal(t, 0, s.procsSize())
}

func init() {
	procTTL = time.Second
}

func TestProcessCallstackProcsTTL(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	r := new(MockResolver)
	c := &config.Config{}

	opts := uint32(sys.SymUndname | sys.SymCaseInsensitive | sys.SymAutoPublics | sys.SymOmapFindNearest | sys.SymDeferredLoads)
	r.On("Initialize", mock.Anything, opts).Return(nil)
	r.On("LoadModule", windows.CurrentProcess(), mock.Anything).Return(nil)
	r.On("GetModuleName", mock.Anything, mock.Anything).Return("C:\\WINDOWS\\System32\\KERNEL32.DLL")
	r.On("GetSymbolNameAndOffset", mock.Anything, mock.Anything).Return("CreateProcessW", 0x54)
	r.On("Cleanup", mock.Anything)

	s := NewSymbolizer(r, c, false)
	require.NotNil(t, s)
	defer s.Close()

	n := 10
	for n > 0 {
		e := &kevent.Kevent{
			Type:      ktypes.CreateProcess,
			Tid:       2484,
			PID:       uint32(os.Getpid()),
			CPU:       1,
			Seq:       2,
			Name:      "CreatedProcess",
			Timestamp: time.Now().Add(time.Millisecond * time.Duration(n)),
			Category:  ktypes.Process,
			Host:      "archrabbit",
			Kparams: kevent.Kparams{
				kparams.Callstack: {Name: kparams.Callstack, Type: kparams.Slice, Value: []va.Address{0x7ffb5c1d0396, 0x7ffb5d8e61f4, 0x7ffb3138592e, 0x7ffb313853b2, 0x2638e59e0a5}},
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

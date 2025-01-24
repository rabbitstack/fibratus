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

package filter

import (
	"github.com/rabbitstack/fibratus/internal/etw/processors"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/pe"
	"github.com/rabbitstack/fibratus/pkg/ps"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/signature"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unsafe"
)

var cfg = &config.Config{
	Kstream: config.KstreamConfig{
		EnableHandleKevents:   true,
		EnableNetKevents:      true,
		EnableRegistryKevents: true,
		EnableFileIOKevents:   true,
		EnableImageKevents:    true,
		EnableThreadKevents:   true,
		EnableMemKevents:      true,
		EnableDNSEvents:       true,
	},
	Filters: &config.Filters{},
	PE:      pe.Config{Enabled: true},
}

func TestFilterCompile(t *testing.T) {
	f := New(`ps.name = 'cmd.exe'`, cfg)
	require.NoError(t, f.Compile())
	f = New(`'cmd.exe'`, cfg)
	require.EqualError(t, f.Compile(), "expected at least one field or operator but zero found")
	f = New(`ps.name`, cfg)
	require.EqualError(t, f.Compile(), "expected at least one field or operator but zero found")
	f = New(`pe.is_exec`, cfg)
	require.NoError(t, f.Compile())
	f = New(`length(pe.imphash) > 0`, cfg)
	require.NoError(t, f.Compile())
	f = New(`ps.name =`, cfg)
	require.EqualError(t, f.Compile(), "ps.name =\n╭─────────^\n|\n|\n╰─────────────────── expected field, bound field, string, number, bool, ip, function")
}

func TestSeqFilterCompile(t *testing.T) {
	f := New(`sequence
|kevt.name = 'CreateProcess'| by ps.exe
|kevt.name = 'CreateFile' and file.operation = 'create'| by file.name
`, cfg)
	require.NoError(t, f.Compile())
	require.NotNil(t, f.GetSequence())
	assert.Len(t, f.GetSequence().Expressions, 2)
	assert.NotNil(t, f.GetSequence().Expressions[0].By)
	assert.True(t, len(f.GetStringFields()) > 0)
}

func TestSeqFilterInvalidBoundRefs(t *testing.T) {
	f := New(`sequence
|kevt.name = 'CreateProcess'| as e1
|kevt.name = 'CreateFile' and file.name = $e.ps.exe |
`, cfg)
	require.Error(t, f.Compile())
	f1 := New(`sequence
|kevt.name = 'CreateProcess'| as e1
|kevt.name = 'CreateFile' and file.name = $e1.ps.exe |
`, cfg)
	require.NoError(t, f1.Compile())
}

func TestStringFields(t *testing.T) {
	f := New(`ps.name = 'cmd.exe' and kevt.name = 'CreateProcess' or kevt.name in ('TerminateProcess', 'CreateFile')`, cfg)
	require.NoError(t, f.Compile())
	assert.Len(t, f.GetStringFields(), 2)
	assert.Len(t, f.GetStringFields()[fields.KevtName], 3)
	assert.Len(t, f.GetStringFields()[fields.PsName], 1)
}

func TestProcFilter(t *testing.T) {
	kpars := kevent.Kparams{
		kparams.Cmdline:         {Name: kparams.Cmdline, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\svchost-fake.exe -k RPCSS"},
		kparams.ProcessName:     {Name: kparams.ProcessName, Type: kparams.AnsiString, Value: "svchost-fake.exe"},
		kparams.ProcessID:       {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(1234)},
		kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.PID, Value: uint32(345)},
		kparams.UserSID:         {Name: kparams.UserSID, Type: kparams.WbemSID, Value: []byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}},
		kparams.Username:        {Name: kparams.Username, Type: kparams.UnicodeString, Value: "loki"},
		kparams.Domain:          {Name: kparams.Domain, Type: kparams.UnicodeString, Value: "TITAN"},
		kparams.ProcessFlags:    {Name: kparams.ProcessFlags, Type: kparams.Flags, Value: uint32(0x000000E)},
	}

	kpars1 := kevent.Kparams{
		kparams.DesiredAccess: {Name: kparams.DesiredAccess, Type: kparams.Flags, Value: uint32(0x1400), Flags: kevent.PsAccessRightFlags},
	}

	ps1 := &pstypes.PS{
		Name:     "wininit.exe",
		Username: "SYSTEM",
		Domain:   "NT AUTHORITY",
		SID:      "S-1-5-18",
		PID:      5042,
		Parent: &pstypes.PS{
			Name: "services.exe",
			SID:  "S-1-5-8",
			PID:  2034,
			Parent: &pstypes.PS{
				Name: "System",
			},
		},
		IsWOW64:     false,
		IsProtected: true,
		IsPackaged:  false,
	}

	kevt := &kevent.Kevent{
		Type:     ktypes.CreateProcess,
		Category: ktypes.Process,
		Kparams:  kpars,
		Name:     "CreateProcess",
		PID:      1023,
		PS: &pstypes.PS{
			Name:     "svchost.exe",
			Cmdline:  "C:\\Windows\\System32\\svchost.exe",
			Parent:   ps1,
			Ppid:     345,
			Username: "SYSTEM",
			Domain:   "NT AUTHORITY",
			SID:      "S-1-5-18",
			Args:     []string{"-k", "DcomLaunch", "-p", "-s", "LSM"},
			Envs:     map[string]string{"ALLUSERSPROFILE": "C:\\ProgramData", "OS": "Windows_NT", "ProgramFiles(x86)": "C:\\Program Files (x86)"},
			Modules: []pstypes.Module{
				{Name: "C:\\Windows\\System32\\kernel32.dll", Size: 12354, Checksum: 23123343, BaseAddress: va.Address(4294066175), DefaultBaseAddress: va.Address(4293993725)},
				{Name: "C:\\Windows\\System32\\user32.dll", Size: 212354, Checksum: 33123343, BaseAddress: va.Address(4277288959), DefaultBaseAddress: va.Address(4293993725)},
			},
			Threads: map[uint32]pstypes.Thread{
				3453: {Tid: 3453, StartAddress: va.Address(144229524944769), IOPrio: 2, PagePrio: 5, KstackBase: va.Address(18446677035730165760), KstackLimit: va.Address(18446677035730137088), UstackLimit: va.Address(86376448), UstackBase: va.Address(86372352)},
				3455: {Tid: 3455, StartAddress: va.Address(140729524944768), IOPrio: 3, PagePrio: 5, KstackBase: va.Address(18446687035730165760), KstackLimit: va.Address(18446698035730165760), UstackLimit: va.Address(86376448), UstackBase: va.Address(46375352)},
			},
			Mmaps: []pstypes.Mmap{
				{Size: 34545, BaseAddress: va.Address(144229524944769), Protection: 4653056, File: "C:\\Windows\\System32\\ucrtbase.dll", Type: "IMAGE"}, //EXECUTE_READWRITE|READONLY
				{Size: 4096, BaseAddress: va.Address(145229445447666), Protection: 12845056, Type: "PAGEFILE"},                                           // READWRITE 12845056
			},
			IsProtected: false,
			IsPackaged:  true,
			IsWOW64:     false,
		},
	}
	kevt.Timestamp, _ = time.Parse(time.RFC3339, "2011-05-03T15:04:05.323Z")

	kevt1 := &kevent.Kevent{
		Type:     ktypes.OpenProcess,
		Category: ktypes.Process,
		Kparams:  kpars1,
		Name:     "OpenProcess",
		PID:      1023,
		PS: &pstypes.PS{
			Name:   "svchost.exe",
			Parent: ps1,
			Ppid:   345,
			Envs:   map[string]string{"ALLUSERSPROFILE": "C:\\ProgramData", "OS": "Windows_NT", "ProgramFiles(x86)": "C:\\Program Files (x86)"},
			Modules: []pstypes.Module{
				{Name: "C:\\Windows\\System32\\kernel32.dll", Size: 12354, Checksum: 23123343, BaseAddress: va.Address(4294066175), DefaultBaseAddress: va.Address(4293993725)},
				{Name: "C:\\Windows\\System32\\user32.dll", Size: 212354, Checksum: 33123343, BaseAddress: va.Address(4277288959), DefaultBaseAddress: va.Address(4293993725)},
			},
		},
	}

	var tests = []struct {
		filter  string
		matches bool
	}{

		{`ps.name = 'svchost.exe'`, true},
		{`ps.name = 'svchot.exe'`, false},
		{`ps.name = 'mimikatz.exe' or ps.name contains 'svc'`, true},
		{`ps.name ~= 'SVCHOST.exe'`, true},
		{`ps.cmdline = 'C:\\Windows\\System32\\svchost.exe'`, true},
		{`ps.child.cmdline = 'C:\\Windows\\system32\\svchost-fake.exe -k RPCSS'`, true},
		{`ps.username = 'SYSTEM'`, true},
		{`ps.domain = 'NT AUTHORITY'`, true},
		{`ps.sid = 'S-1-5-18'`, true},
		{`ps.pid = 1023`, true},
		{`ps.child.sid = 'S-1-5-18'`, true},
		{`ps.sibling.pid = 1234`, true},
		{`ps.child.pid = 1234`, true},
		{`ps.child.uuid > 0`, true},
		{`ps.parent.pid = 5042`, true},
		{`ps.sibling.name = 'svchost-fake.exe'`, true},
		{`ps.child.name = 'svchost-fake.exe'`, true},
		{`ps.sibling.username = 'loki'`, true},
		{`ps.child.username = 'loki'`, true},
		{`ps.sibling.domain = 'TITAN'`, true},
		{`ps.child.domain = 'TITAN'`, true},
		{`ps.parent.username = 'SYSTEM'`, true},
		{`ps.parent.domain = 'NT AUTHORITY'`, true},
		{`ps.envs[ALLUSERSPROFILE] = 'C:\\ProgramData'`, true},
		{`ps.envs[ALLUSER] = 'C:\\ProgramData'`, true},
		{`ps.envs[ProgramFiles] = 'C:\\Program Files (x86)'`, true},
		{`ps.envs[windir] = 'C:\\WINDOWS'`, false},
		{`ps.envs in ('ALLUSERSPROFILE:C:\\ProgramData')`, true},
		{`foreach(ps.envs, $env, substr($env, 0, indexof($env, ':')) = 'OS')`, true},

		{`ps.child.is_wow64`, true},
		{`ps.child.is_packaged`, true},
		{`ps.child.is_protected`, true},
		{`ps.is_wow64`, false},
		{`ps.is_packaged`, true},
		{`ps.is_protected`, false},
		{`ps.parent.is_wow64`, false},
		{`ps.parent.is_packaged`, false},
		{`ps.parent.is_protected`, true},
		{`kevt.name = 'CreateProcess' and ps.name contains 'svchost'`, true},

		{`ps.modules IN ('kernel32.dll')`, true},
		{`kevt.name = 'CreateProcess' and kevt.pid != ps.ppid`, true},
		{`ps.parent.name = 'wininit.exe'`, true},

		{`ps.ancestor[0] = 'svchost.exe'`, false},
		{`ps.ancestor[0] = 'wininit.exe'`, true},
		{`ps.ancestor[1] = 'services.exe'`, true},
		{`ps.ancestor[2] = 'System'`, true},
		{`ps.ancestor[3] = ''`, true},
		{`ps.ancestor intersects ('wininit.exe', 'services.exe', 'System')`, true},

		{`foreach(ps._ancestors, $proc, $proc.name in ('wininit.exe', 'services.exe', 'System'))`, true},
		{`foreach(ps._ancestors, $proc, $proc.name in ('wininit.exe', 'services.exe', 'System') and ps.is_packaged, ps.is_packaged)`, true},
		{`foreach(ps._ancestors, $proc, $proc.name not in ('svchost.exe', 'WmiPrvSE.exe'))`, true},
		{`foreach(ps._ancestors, $proc, $proc.sid = 'S-1-5-8'))`, true},
		{`foreach(ps._ancestors, $proc, $proc.name endswith 'ices.exe'))`, true},
		{`foreach(ps._ancestors, $proc, $proc.pid in (2034, 343) and $proc.name = 'services.exe')`, true},
		{`foreach(ps._ancestors, $proc, $proc.username = 'SYSTEM')`, true},
		{`foreach(ps._ancestors, $proc, $proc.domain = 'NT AUTHORITY')`, true},
		{`foreach(ps._ancestors, $proc, $proc.username = upper('system'))`, true},

		{`ps.args intersects ('-k', 'DcomLaunch')`, true},
		{`ps.args intersects ('-w', 'DcomLaunch')`, false},
		{`ps.args iintersects ('-K', 'DComLaunch')`, true},
		{`ps.args iintersects ('-W', 'DcomLaunch')`, false},

		{`foreach(ps.modules, $mod, $mod imatches 'us?r32.dll')`, true},
		{`foreach(ps._modules, $mod, $mod.path imatches '?:\\Windows\\System32\\us?r32.dll')`, true},
		{`foreach(ps._modules, $mod, $mod.name imatches 'USER32.*')`, true},
		{`foreach(ps._modules, $mod, $mod.name imatches 'USER32.*' and $mod.size >= 212354)`, true},
		{`foreach(ps._modules, $mod, ($mod.name imatches 'USER32.*' and $mod.size >= 212354) or $mod.name imatches '*winhttp.dll')`, true},
		{`foreach(ps._modules, $mod, ($mod.name imatches 'winhttp.dll' and $mod.size >= 11212354) or $mod.name matches 'user32.dll')`, true},
		{`foreach(ps._modules, $mod, $mod.checksum = 23123343)`, true},
		{`foreach(ps._modules, $mod, $mod.address = 'fff23fff')`, true},

		{`foreach(ps._threads, $t, $t.start_address = '7ffe2557ff80')`, true},
		{`foreach(ps._threads, $t, $t.start_address = '7ffe2557ff80' or $t.user_stack_base = '2251760466')`, true},
		{`foreach(ps._threads, $t, $t.tid = 3453)`, true},
		{`foreach(ps._threads, $t, $t.start_address = '7ffe2557ff80' or $t.user_stack_base = '2251760466')`, true},
		{`foreach(ps._threads, $t, $t.kernel_stack_base = 'ffffcc1fcf800000' and $t.kernel_stack_limit = 'ffffd620f297b000')`, true},

		{`foreach(ps._mmaps, $mmap, $mmap.protection = 'RW')`, true},
		{`foreach(ps._mmaps, $mmap, $mmap.path = 'C:\\Windows\\System32\\ucrtbase.dll' and $mmap.type = 'IMAGE')`, true},
		{`foreach(ps._mmaps, $mmap, $mmap.address = '8415dd81bff2')`, true},
		{`foreach(ps._mmaps, $mmap, $mmap.size = 4096)`, true},
	}

	psnap := new(ps.SnapshotterMock)
	psnap.On("FindAndPut", uint32(1234)).Return(ps1)

	for i, tt := range tests {
		f := New(tt.filter, cfg, WithPSnapshotter(psnap))
		err := f.Compile()
		if err != nil {
			t.Fatal(err)
		}
		matches := f.Run(kevt)
		if matches != tt.matches {
			t.Errorf("%d. %q ps filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}

	var tests1 = []struct {
		filter  string
		matches bool
	}{

		{`ps.access.mask.names in ('QUERY_INFORMATION', 'QUERY_LIMITED_INFORMATION')`, true},
		{`ps.access.mask.names in ('ALL_ACCESS')`, false},
	}

	for i, tt := range tests1 {
		f := New(tt.filter, cfg)
		err := f.Compile()
		if err != nil {
			t.Fatal(err)
		}
		matches := f.Run(kevt1)
		if matches != tt.matches {
			t.Errorf("%d. %q ps filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}
}

func TestThreadFilter(t *testing.T) {
	kpars := kevent.Kparams{
		kparams.ProcessID:    {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(os.Getpid())},
		kparams.ThreadID:     {Name: kparams.ThreadID, Type: kparams.TID, Value: uint32(3453)},
		kparams.BasePrio:     {Name: kparams.BasePrio, Type: kparams.Uint8, Value: uint8(13)},
		kparams.StartAddress: {Name: kparams.StartAddress, Type: kparams.Address, Value: uint64(140729524944768)},
		kparams.TEB:          {Name: kparams.TEB, Type: kparams.Address, Value: uint64(614994620416)},
		kparams.IOPrio:       {Name: kparams.IOPrio, Type: kparams.Uint8, Value: uint8(2)},
		kparams.KstackBase:   {Name: kparams.KstackBase, Type: kparams.Address, Value: uint64(18446677035730165760)},
		kparams.KstackLimit:  {Name: kparams.KstackLimit, Type: kparams.Address, Value: uint64(18446677035730137088)},
		kparams.PagePrio:     {Name: kparams.PagePrio, Type: kparams.Uint8, Value: uint8(5)},
		kparams.UstackBase:   {Name: kparams.UstackBase, Type: kparams.Address, Value: uint64(86376448)},
		kparams.UstackLimit:  {Name: kparams.UstackLimit, Type: kparams.Address, Value: uint64(86372352)},
	}
	kevt := &kevent.Kevent{
		Type:     ktypes.CreateThread,
		Kparams:  kpars,
		Name:     "CreateThread",
		PID:      windows.GetCurrentProcessId(),
		Category: ktypes.Thread,
		PS: &pstypes.PS{
			Name: "svchost.exe",
			Envs: map[string]string{"ALLUSERSPROFILE": "C:\\ProgramData", "OS": "Windows_NT", "ProgramFiles(x86)": "C:\\Program Files (x86)"},
		},
	}

	// simulate unbacked RWX frame
	base, err := windows.VirtualAlloc(0, 1024, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	require.NoError(t, err)
	defer func() {
		_ = windows.VirtualFree(base, 1024, windows.MEM_DECOMMIT)
	}()
	insns := []byte{
		0x4C, 0x8B, 0xD1, // mov r10, rcx
		0xB8, 0x55, 0x0, 0x0, 0x0, // mov eax, 55h
		0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01, // test byte ptr[7FFE0308h]
		0x0F, 0x05, // syscall
		0xC3, // ret
	}
	require.NoError(t, windows.WriteProcessMemory(windows.CurrentProcess(), base, &insns[0], uintptr(len(insns)), nil))

	kevt.Callstack.Init(8)
	kevt.Callstack.PushFrame(kevent.Frame{PID: kevt.PID, Addr: 0x2638e59e0a5, Offset: 0, Symbol: "?", Module: "unbacked"})
	kevt.Callstack.PushFrame(kevent.Frame{PID: kevt.PID, Addr: va.Address(base), Offset: 0, Symbol: "?", Module: "unbacked"})
	kevt.Callstack.PushFrame(kevent.Frame{PID: kevt.PID, Addr: 0x7ffb313853b2, Offset: 0x10a, Symbol: "Java_java_lang_ProcessImpl_create", Module: "C:\\Program Files\\JetBrains\\GoLand 2021.2.3\\jbr\\bin\\java.dll"})
	kevt.Callstack.PushFrame(kevent.Frame{PID: kevt.PID, Addr: 0x7ffb3138592e, Offset: 0x3a2, Symbol: "Java_java_lang_ProcessImpl_waitForTimeoutInterruptibly", Module: "C:\\Program Files\\JetBrains\\GoLand 2021.2.3\\jbr\\bin\\java.dll"})
	kevt.Callstack.PushFrame(kevent.Frame{PID: kevt.PID, Addr: 0x7ffb5d8e61f4, Offset: 0x54, Symbol: "CreateProcessW", Module: "C:\\WINDOWS\\System32\\KERNEL32.DLL"})
	kevt.Callstack.PushFrame(kevent.Frame{PID: kevt.PID, Addr: 0x7ffb5c1d0396, Offset: 0x66, Symbol: "CreateProcessW", Module: "C:\\WINDOWS\\System32\\KERNELBASE.dll"})
	kevt.Callstack.PushFrame(kevent.Frame{PID: kevt.PID, Addr: 0xfffff8072ebc1f6f, Offset: 0x4ef, Symbol: "FltRequestFileInfoOnCreateCompletion", Module: "C:\\WINDOWS\\System32\\drivers\\FLTMGR.SYS"})
	kevt.Callstack.PushFrame(kevent.Frame{PID: kevt.PID, Addr: 0xfffff8072eb8961b, Offset: 0x20cb, Symbol: "FltGetStreamContext", Module: "C:\\WINDOWS\\System32\\drivers\\FLTMGR.SYS"})

	var tests = []struct {
		filter  string
		matches bool
	}{

		{`thread.ustack.base = '5260000'`, true},
		{`thread.ustack.limit = '525f000'`, true},
		{`thread.kstack.base = 'ffffc307810d6000'`, true},
		{`thread.kstack.limit = 'ffffc307810cf000'`, true},
		{`thread.start_address = '7ffe2557ff80'`, true},
		{`thread.teb_address = '8f30893000'`, true},
		{`thread.callstack.summary = 'KERNELBASE.dll|KERNEL32.DLL|java.dll|unbacked'`, true},
		{`thread.callstack.detail icontains 'C:\\WINDOWS\\System32\\KERNELBASE.dll!CreateProcessW+0x66'`, true},
		{`thread.callstack.modules in ('C:\\WINDOWS\\System32\\KERNELBASE.dll', 'C:\\Program Files\\JetBrains\\GoLand 2021.2.3\\jbr\\bin\\java.dll')`, true},
		{`thread.callstack.symbols imatches ('KERNELBASE.dll!CreateProcess*', 'Java_java_lang_ProcessImpl_create')`, true},
		{`thread.callstack.protections in ('RWX')`, true},
		{`thread.callstack.allocation_sizes > 0`, false},
		{`length(thread.callstack.callsite_leading_assembly) > 0`, true},
		{`thread.callstack.callsite_trailing_assembly matches ('*mov r10, rcx|mov eax, 0x*|syscall*')`, true},
		{`thread.callstack.is_unbacked`, true},

		{`foreach(thread._callstack, $frame, $frame.address = '2638e59e0a5' or $frame.address = '7ffb5c1d0396')`, true},
		{`foreach(thread._callstack, $frame, $frame.address = 'fffff8072ebc1f6f' or $frame.address = 'fffff8072eb8961b')`, true},
		{`foreach(thread._callstack, $frame, $frame.address = 'ffffffffff')`, false},
		{`foreach(thread._callstack, $frame, $frame.symbol imatches '?:\\Program Files\\*java.dll!Java_java_lang_ProcessImpl_create')`, true},
		{`foreach(thread._callstack, $frame, $frame.symbol imatches '*CreateProcessW')`, true},
		{`foreach(thread._callstack, $frame, $frame.module = 'C:\\Program Files\\JetBrains\\GoLand 2021.2.3\\jbr\\bin\\java.dll')`, true},
		{`foreach(thread._callstack, $frame, base($frame.module) = 'java.dll' and $frame.symbol imatches '*Java_java_lang_ProcessImpl_create')`, true},
		{`foreach(thread._callstack, $frame, $frame.offset = 266)`, true},
		{`foreach(thread._callstack, $frame, $frame.is_unbacked = true)`, true},
		{`ps.name = 'svchost.exe' and not foreach(thread._callstack, $frame, $frame.symbol imatches '*LoadLibrary')`, true},
		{`foreach(thread._callstack, $frame, $frame.allocation_size = 0)`, true},
		{`foreach(thread._callstack, $frame, $frame.protection = 'RWX')`, true},
		{`foreach(thread._callstack, $frame, $frame.callsite_trailing_assembly matches '*mov r10, rcx|mov eax, 0x*|syscall*' and $frame.module = 'unbacked')`, true},
	}

	for i, tt := range tests {
		f := New(tt.filter, cfg)
		err := f.Compile()
		if err != nil {
			t.Fatal(err)
		}
		matches := f.Run(kevt)
		if matches != tt.matches {
			t.Errorf("%d. %q thread filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}

	// spawn a new process
	var si windows.StartupInfo
	si.Flags = windows.STARTF_USESHOWWINDOW
	var pi windows.ProcessInformation

	argv := windows.StringToUTF16Ptr(filepath.Join(os.Getenv("windir"), "regedit.exe"))

	err = windows.CreateProcess(
		nil,
		argv,
		nil,
		nil,
		true,
		0,
		nil,
		nil,
		&si,
		&pi)
	require.NoError(t, err)

	for {
		if sys.IsProcessRunning(pi.Process) {
			break
		}
		time.Sleep(time.Millisecond * 100)
		log.Infof("%d pid not yet ready", pi.ProcessId)
	}
	defer windows.TerminateProcess(pi.Process, 0)

	kevt.PID = pi.ProcessId

	// try until a valid address is returned
	// or fail if max attempts are exhausted
	j := 50
	ntdll := getNtdllAddress(pi.ProcessId)
	for ntdll == 0 && j > 0 {
		ntdll = getNtdllAddress(pi.ProcessId)
		time.Sleep(time.Millisecond * 250)
		j--
	}

	// overwrite ntdll address with dummy bytes
	// to reproduce module stomping technique
	var protect uint32
	require.NoError(t, windows.VirtualProtectEx(pi.Process, ntdll, uintptr(len(insns)), windows.PAGE_EXECUTE_READWRITE, &protect))

	var n uintptr
	require.NoError(t, windows.WriteProcessMemory(pi.Process, ntdll, &insns[0], uintptr(len(insns)), &n))

	kevt.Callstack[0] = kevent.Frame{PID: kevt.PID, Addr: va.Address(ntdll), Offset: 0, Symbol: "?", Module: "C:\\Windows\\System32\\ntdll.dll"}

	var tests1 = []struct {
		filter  string
		matches bool
	}{

		{`thread.callstack.allocation_sizes > 0`, true},
		{`foreach(thread._callstack, $frame, $frame.allocation_size > 2048 and $frame.protection = 'RWXC')`, true},
	}

	for i, tt := range tests1 {
		f := New(tt.filter, cfg)
		err := f.Compile()
		if err != nil {
			t.Fatal(err)
		}
		matches := f.Run(kevt)
		if matches != tt.matches {
			t.Errorf("%d. %q thread filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}
}

func TestFileFilter(t *testing.T) {
	kevt := &kevent.Kevent{
		Type:        ktypes.CreateFile,
		Tid:         2484,
		PID:         859,
		CPU:         1,
		Seq:         2,
		Name:        "CreateFile",
		Category:    ktypes.File,
		Host:        "archrabbit",
		Description: "Creates or opens a new file, directory, I/O device, pipe, console",
		Kparams: kevent.Kparams{
			kparams.FileObject:    {Name: kparams.FileObject, Type: kparams.Uint64, Value: uint64(12456738026482168384)},
			kparams.FilePath:      {Name: kparams.FilePath, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\user32.dll"},
			kparams.FileType:      {Name: kparams.FileType, Type: kparams.AnsiString, Value: "file"},
			kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.AnsiString, Value: "open"},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	var tests = []struct {
		filter  string
		matches bool
	}{

		{`file.name = 'user32.dll'`, true},
		{`file.path = 'C:\\Windows\\system32\\user32.dll'`, true},
		{`file.extension  = '.dll'`, true},
		{`file.extension not contains '.exe'`, true},
		{`file.extension contains '.exe' or (file.extension contains '.dll' and file.name endswith 'user32.dll')`, true},
		{`file.extension = '.dll' or (file.extension contains '.exe' and file.name endswith 'kernel32.dll')`, true},
		{`file.extension not contains '.exe' and file.extension contains '.dll'`, true},
		{`file.extension not contains '.exe' and file.extension not contains '.com'`, true},
		{`file.extension not contains '.exe' and file.extension not contains '.com' and file.extension not in ('.vba', '.exe')`, true},
		{`file.extension not in ('.exe', '.com')`, true},
		{`file.extension not in ('.exe', '.dll')`, false},
		{`file.path matches 'C:\\*\\user32.dll'`, true},
		{`file.path not matches 'C:\\*.exe'`, true},
		{`file.path imatches 'C:\\*\\USER32.dll'`, true},
		{`file.path matches ('C:\\*\\user3?.dll', 'C:\\*\\user32.*')`, true},
		{`file.path contains ('C:\\Windows\\system32\\kernel32.dll', 'C:\\Windows\\system32\\user32.dll')`, true},
		{`file.path not matches ('C:\\*.exe', 'C:\\Windows\\*.com')`, true},
		{`file.path endswith ('.exe', 'kernel32.dll', 'user32.dll')`, true},
		{`file.path iendswith ('.EXE', 'KERNEL32.dll', 'user32.dll')`, true},
		{`file.path istartswith ('C:\\WINDOWS', 'KERNEL32.dll', 'user32.dll')`, true},
		{`file.path iin ('C:\\WINDOWS\\system32\\user32.dll')`, true},
		{`file.path fuzzy 'C:\\Windows\\system32\\ser3ll'`, true},
		{`file.path ifuzzy 'C:\\WINDOWS\\sYS\\ser3ll'`, true},
		{`file.path ifuzzy 'C:\\WINDOWS\\sYS\\32dll'`, true},
		{`file.path fuzzy ('C:\\Windows\\system32\\kernel', 'C:\\Windows\\system32\\ser3ll')`, true},
		{`file.path ifuzzynorm 'C:\\WINDOWS\\sÝS\\32dll'`, true},
		{`base(file.path) = 'user32.dll'`, true},
		{`ext(base(file.path)) = '.dll'`, true},
		{`base(file.path, false) = 'user32'`, true},
		{`dir(file.path) = 'C:\\Windows\\system32'`, true},
		{`ext(file.path) = '.dll'`, true},
		{`ext(file.path, false) = 'dll'`, true},
		{`is_abs(file.path)`, true},
		{`is_abs(base(file.path))`, false},
		{`file.path iin glob('C:\\Windows\\System32\\*.dll')`, true},
		{`volume(file.path) = 'C:'`, true},
	}

	for i, tt := range tests {
		f := New(tt.filter, cfg)
		err := f.Compile()
		if err != nil {
			t.Fatal(err)
		}
		matches := f.Run(kevt)
		if matches != tt.matches {
			t.Errorf("%d. %q file filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}
}

func TestFileInfoFilter(t *testing.T) {
	var tests = []struct {
		f       string
		e       *kevent.Kevent
		matches bool
	}{
		{
			`file.info_class = 'Allocation'`,
			&kevent.Kevent{
				Category: ktypes.File,
				Type:     ktypes.SetFileInformation,
				Name:     "SetFileInformation",
				Kparams: kevent.Kparams{
					kparams.FileInfoClass: {Name: kparams.FileInfoClass, Type: kparams.Enum, Value: fs.AllocationClass, Enum: fs.FileInfoClasses},
				},
			},
			true,
		},
		{
			`file.info.allocation_size = 64500`,
			&kevent.Kevent{
				Category: ktypes.File,
				Type:     ktypes.SetFileInformation,
				Name:     "SetFileInformation",
				Kparams: kevent.Kparams{
					kparams.FileInfoClass: {Name: kparams.FileInfoClass, Type: kparams.Enum, Value: fs.AllocationClass, Enum: fs.FileInfoClasses},
					kparams.FileExtraInfo: {Name: kparams.FileExtraInfo, Type: kparams.Uint64, Value: uint64(64500)},
				},
			},
			true,
		},
		{
			`file.info.eof_size = 64500`,
			&kevent.Kevent{
				Category: ktypes.File,
				Type:     ktypes.SetFileInformation,
				Name:     "SetFileInformation",
				Kparams: kevent.Kparams{
					kparams.FileInfoClass: {Name: kparams.FileInfoClass, Type: kparams.Enum, Value: fs.EOFClass, Enum: fs.FileInfoClasses},
					kparams.FileExtraInfo: {Name: kparams.FileExtraInfo, Type: kparams.Uint64, Value: uint64(64500)},
				},
			},
			true,
		},
		{
			`file.info.eof_size = 64500`,
			&kevent.Kevent{
				Category: ktypes.File,
				Type:     ktypes.SetFileInformation,
				Name:     "SetFileInformation",
				Kparams: kevent.Kparams{
					kparams.FileInfoClass: {Name: kparams.FileInfoClass, Type: kparams.Enum, Value: fs.DispositionClass, Enum: fs.FileInfoClasses},
					kparams.FileExtraInfo: {Name: kparams.FileExtraInfo, Type: kparams.Uint64, Value: uint64(1)},
				},
			},
			false,
		},
		{
			`file.info.is_disposition_delete_file = true`,
			&kevent.Kevent{
				Category: ktypes.File,
				Type:     ktypes.DeleteFile,
				Name:     "DeleteFile",
				Kparams: kevent.Kparams{
					kparams.FileInfoClass: {Name: kparams.FileInfoClass, Type: kparams.Enum, Value: fs.DispositionClass, Enum: fs.FileInfoClasses},
					kparams.FileExtraInfo: {Name: kparams.FileExtraInfo, Type: kparams.Uint64, Value: uint64(1)},
				},
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.f, func(t *testing.T) {
			f := New(tt.f, cfg)
			err := f.Compile()
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, tt.matches, f.Run(tt.e))
		})
	}
}

func TestKeventFilter(t *testing.T) {
	kevt := &kevent.Kevent{
		Type:        ktypes.CreateFile,
		Tid:         2484,
		PID:         859,
		CPU:         1,
		Seq:         2,
		Name:        "CreateFile",
		Category:    ktypes.File,
		Host:        "archrabbit",
		Description: "Creates or opens a new file, directory, I/O device, pipe, console",
		Kparams: kevent.Kparams{
			kparams.ProcessID:     {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(3434)},
			kparams.FileObject:    {Name: kparams.FileObject, Type: kparams.Uint64, Value: uint64(12456738026482168384)},
			kparams.FilePath:      {Name: kparams.FilePath, Type: kparams.UnicodeString, Value: "\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll"},
			kparams.FileType:      {Name: kparams.FileType, Type: kparams.AnsiString, Value: "file"},
			kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.AnsiString, Value: "open"},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barz"},
	}

	kevt.Timestamp, _ = time.Parse(time.RFC3339, "2011-05-03T15:04:05.323Z")

	var tests = []struct {
		filter  string
		matches bool
	}{

		{`kevt.seq = 2`, true},
		{`kevt.pid = 859`, true},
		{`kevt.tid = 2484`, true},
		{`kevt.cpu = 1`, true},
		{`kevt.name = 'CreateFile'`, true},
		{`kevt.category = 'file'`, true},
		{`kevt.host = 'archrabbit'`, true},
		{`kevt.nparams = 5`, true},
		{`kevt.arg[file_path] = '\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll'`, true},
		{`kevt.arg[type] = 'file'`, true},
		{`kevt.arg[pid] = 3434`, true},

		{`kevt.desc contains 'Creates or opens a new file'`, true},

		{`kevt.date.d = 3 AND kevt.date.m = 5 AND kevt.time.s = 5 AND kevt.time.m = 4 and kevt.time.h = 15`, true},
		{`kevt.time = '15:04:05'`, true},
		{`concat(kevt.name, kevt.host, kevt.nparams) = 'CreateFilearchrabbit5'`, true},
		{`ltrim(kevt.host, 'arch') = 'rabbit'`, true},
		{`concat(ltrim(kevt.name, 'Create'), kevt.host) = 'Filearchrabbit'`, true},
		{`lower(rtrim(kevt.name, 'File')) = 'create'`, true},
		{`upper(rtrim(kevt.name, 'File')) = 'CREATE'`, true},
		{`replace(kevt.host, 'rabbit', '_bunny') = 'arch_bunny'`, true},
		{`replace(kevt.host, 'rabbit', '_bunny', '_bunny', 'bunny') = 'archbunny'`, true},
		{`split(file.path, '\\') IN ('windows', 'system32')`, true},
		{`length(file.path) = 51`, true},
		{`indexof(file.path, '\\') = 0`, true},
		{`indexof(file.path, '\\', 'last') = 40`, true},
		{`indexof(file.path, 'h2', 'any') = 22`, true},
		{`substr(file.path, indexof(file.path, '\\'), indexof(file.path, '\\Hard')) = '\\Device'`, true},
		{`substr(kevt.desc, indexof(kevt.desc, '\\'), indexof(kevt.desc, 'NOT')) = 'Creates or opens a new file, directory, I/O device, pipe, console'`, true},
		{`entropy(file.path) > 120`, true},
		{`regex(file.path, '\\\\Device\\\\HarddiskVolume[2-9]+\\\\.*')`, true},
	}

	for i, tt := range tests {
		f := New(tt.filter, cfg)
		err := f.Compile()
		if err != nil {
			t.Fatal(err)
		}
		matches := f.Run(kevt)
		if matches != tt.matches {
			t.Errorf("%d. %q kevt filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}
}

func TestNetFilter(t *testing.T) {
	kevt := &kevent.Kevent{
		Type: ktypes.SendTCPv4,
		Tid:  2484,
		PID:  859,
		PS: &pstypes.PS{
			Name: "cmd.exe",
		},
		Category: ktypes.Net,
		Kparams: kevent.Kparams{
			kparams.NetDport: {Name: kparams.NetDport, Type: kparams.Uint16, Value: uint16(443)},
			kparams.NetSport: {Name: kparams.NetSport, Type: kparams.Uint16, Value: uint16(43123)},
			kparams.NetSIP:   {Name: kparams.NetSIP, Type: kparams.IPv4, Value: net.ParseIP("127.0.0.1")},
			kparams.NetDIP:   {Name: kparams.NetDIP, Type: kparams.IPv4, Value: net.ParseIP("216.58.201.174")},
		},
	}

	var tests = []struct {
		filter  string
		matches bool
	}{

		{`net.dip = 216.58.201.174`, true},
		{`net.dip != 216.58.201.174`, false},
		{`net.dip != 116.58.201.174`, true},
		{`net.dip startswith '216.58'`, true},
		{`net.dip endswith '.174'`, true},
		{`net.dport = 443`, true},
		{`net.dport in (123, 443)`, true},
		{`net.dip != 116.58.201.174`, true},
		{`net.dip not in ('116.58.201.172', '16.58.201.176')`, true},
		{`net.dip not in (116.58.201.172, 16.58.201.176)`, true},
		{`ps.name = 'cmd.exe' and not cidr_contains(net.sip, '227.0.0.1/12', '8.2.3.0/4')`, true},
		{`ps.name = 'cmd.exe' and not ((net.sip in (222.1.1.1)) or (net.sip in (12.3.4.5)))`, true},
		{`cidr_contains(net.dip, '216.58.201.1/24') = true`, true},
		{`cidr_contains(net.dip, '226.58.201.1/24') = false`, true},
		{`cidr_contains(net.dip, '216.58.201.1/24', '216.58.201.10/24') = true and kevt.pid = 859`, true},
		{`kevt.name not in ('CreateProcess', 'Connect') and cidr_contains(net.dip, '216.58.201.1/24') = true`, true},
	}

	for i, tt := range tests {
		f := New(tt.filter, cfg)
		err := f.Compile()
		if err != nil {
			t.Fatal(err)
		}
		matches := f.Run(kevt)
		if matches != tt.matches {
			t.Errorf("%d. %q net filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}

	kevt1 := &kevent.Kevent{
		Type: ktypes.SendTCPv4,
		Tid:  2484,
		PID:  859,
		PS: &pstypes.PS{
			Name: "cmd.exe",
		},
		Category: ktypes.Net,
		Kparams: kevent.Kparams{
			kparams.NetDport: {Name: kparams.NetDport, Type: kparams.Uint16, Value: uint16(53)},
			kparams.NetSport: {Name: kparams.NetSport, Type: kparams.Uint16, Value: uint16(43123)},
			kparams.NetSIP:   {Name: kparams.NetSIP, Type: kparams.IPv4, Value: net.ParseIP("127.0.0.1")},
			kparams.NetDIP:   {Name: kparams.NetDIP, Type: kparams.IPv4, Value: net.ParseIP("8.8.8.8")},
		},
	}

	var tests1 = []struct {
		filter  string
		matches bool
	}{

		{`net.dip.names in ('dns.google.')`, true},
		{`length(net.sip.names) > 0`, true},
	}

	for i, tt := range tests1 {
		f := New(tt.filter, cfg)
		err := f.Compile()
		if err != nil {
			t.Fatal(err)
		}
		matches := f.Run(kevt1)
		if matches != tt.matches {
			t.Errorf("%d. %q net filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}
}

func TestRegistryFilter(t *testing.T) {
	kevt := &kevent.Kevent{
		Type:     ktypes.RegSetValue,
		Tid:      2484,
		PID:      859,
		Category: ktypes.Registry,
		Kparams: kevent.Kparams{
			kparams.RegPath:      {Name: kparams.RegPath, Type: kparams.UnicodeString, Value: `HKEY_LOCAL_MACHINE\SYSTEM\Setup\Pid`},
			kparams.RegValue:     {Name: kparams.RegValue, Type: kparams.Uint32, Value: uint32(10234)},
			kparams.RegValueType: {Name: kparams.RegValueType, Type: kparams.AnsiString, Value: "DWORD"},
			kparams.NTStatus:     {Name: kparams.NTStatus, Type: kparams.AnsiString, Value: "success"},
			kparams.RegKeyHandle: {Name: kparams.RegKeyHandle, Type: kparams.Address, Value: uint64(18446666033449935464)},
		},
	}

	var tests = []struct {
		filter  string
		matches bool
	}{

		{`registry.status startswith ('key not', 'succ')`, true},
		{`registry.path = 'HKEY_LOCAL_MACHINE\\SYSTEM\\Setup\\Pid'`, true},
		{`registry.key.name icontains ('Setup', 'setup')`, true},
		{`registry.value = 10234`, true},
		{`registry.value.type in ('DWORD', 'QWORD')`, true},
		{`MD5(registry.path) = 'eab870b2a516206575d2ffa2b98d8af5'`, true},
	}

	for i, tt := range tests {
		f := New(tt.filter, cfg)
		err := f.Compile()
		if err != nil {
			t.Fatal(err)
		}
		matches := f.Run(kevt)
		if matches != tt.matches {
			t.Errorf("%d. %q registry filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}
}

func TestImageFilter(t *testing.T) {
	kevt := &kevent.Kevent{
		Type:     ktypes.LoadImage,
		Category: ktypes.Image,
		Kparams: kevent.Kparams{
			kparams.ImagePath:           {Name: kparams.ImagePath, Type: kparams.UnicodeString, Value: filepath.Join(os.Getenv("windir"), "System32", "kernel32.dll")},
			kparams.ProcessID:           {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(1023)},
			kparams.ImageCheckSum:       {Name: kparams.ImageCheckSum, Type: kparams.Uint32, Value: uint32(2323432)},
			kparams.ImageBase:           {Name: kparams.ImageBase, Type: kparams.Address, Value: uint64(0x7ffb313833a3)},
			kparams.ImageSignatureType:  {Name: kparams.ImageSignatureType, Type: kparams.Enum, Value: uint32(1), Enum: signature.Types},
			kparams.ImageSignatureLevel: {Name: kparams.ImageSignatureLevel, Type: kparams.Enum, Value: uint32(4), Enum: signature.Levels},
		},
	}

	var tests = []struct {
		filter  string
		matches bool
	}{

		{`image.signature.type = 'EMBEDDED'`, true},
		{`image.signature.level = 'AUTHENTICODE'`, true},
		{`image.pid = 1023`, true},
		{`image.path endswith 'System32\\kernel32.dll'`, true},
		{`image.name = 'kernel32.dll'`, true},
		{`image.checksum = 2323432`, true},
		{`image.base.address = '7ffb313833a3'`, true},
		{`image.cert.issuer icontains 'Microsoft Windows'`, true},
		{`image.cert.subject icontains 'Microsoft Corporation'`, true},
		{`image.is_dotnet`, false},
	}

	for i, tt := range tests {
		f := New(tt.filter, cfg)
		err := f.Compile()
		if err != nil {
			t.Fatal(err)
		}
		matches := f.Run(kevt)
		if matches != tt.matches {
			t.Errorf("%d. %q image filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}

	// check signatures expectations
	sig := signature.GetSignatures().GetSignature(0x7ffb313833a3)
	assert.NotNil(t, sig)
	assert.Equal(t, filepath.Join(os.Getenv("windir"), "System32", "kernel32.dll"), sig.Filename)
	assert.Equal(t, signature.Embedded, sig.Type)
	assert.Equal(t, signature.AuthenticodeLevel, sig.Level)

	// now exercise unsigned/unchecked signature
	kevt1 := &kevent.Kevent{
		Type:     ktypes.LoadImage,
		Category: ktypes.Image,
		Kparams: kevent.Kparams{
			kparams.ImagePath:           {Name: kparams.ImagePath, Type: kparams.UnicodeString, Value: filepath.Join(os.Getenv("windir"), "System32", "kernel32.dll")},
			kparams.ProcessID:           {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(1023)},
			kparams.ImageCheckSum:       {Name: kparams.ImageCheckSum, Type: kparams.Uint32, Value: uint32(2323432)},
			kparams.ImageBase:           {Name: kparams.ImageBase, Type: kparams.Address, Value: uint64(0x7ccb313833a3)},
			kparams.ImageSignatureType:  {Name: kparams.ImageSignatureType, Type: kparams.Enum, Value: uint32(0), Enum: signature.Types},
			kparams.ImageSignatureLevel: {Name: kparams.ImageSignatureLevel, Type: kparams.Enum, Value: uint32(0), Enum: signature.Levels},
		},
	}

	var tests1 = []struct {
		filter  string
		matches bool
	}{

		{`image.signature.type = 'EMBEDDED'`, true},
		{`image.signature.level = 'AUTHENTICODE'`, true},
		{`image.pid = 1023`, true},
		{`image.name endswith 'kernel32.dll'`, true},
		{`image.checksum = 2323432`, true},
		{`image.base.address = '7ccb313833a3'`, true},
		{`image.cert.issuer icontains 'Microsoft Windows'`, true},
		{`image.cert.subject icontains 'Microsoft Corporation'`, true},
	}

	for i, tt := range tests1 {
		f := New(tt.filter, cfg)
		err := f.Compile()
		if err != nil {
			t.Fatal(err)
		}
		matches := f.Run(kevt1)
		if matches != tt.matches {
			t.Errorf("%d. %q image filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}

	assert.NotNil(t, signature.GetSignatures().GetSignature(0x7ccb313833a3))

	kevt2 := &kevent.Kevent{
		Type:     ktypes.LoadImage,
		Category: ktypes.Image,
		Kparams: kevent.Kparams{
			kparams.ImagePath:           {Name: kparams.ImagePath, Type: kparams.UnicodeString, Value: "_fixtures\\mscorlib.dll"},
			kparams.ProcessID:           {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(1023)},
			kparams.ImageCheckSum:       {Name: kparams.ImageCheckSum, Type: kparams.Uint32, Value: uint32(2323432)},
			kparams.ImageBase:           {Name: kparams.ImageBase, Type: kparams.Address, Value: uint64(0xfff313833a3)},
			kparams.ImageSignatureType:  {Name: kparams.ImageSignatureType, Type: kparams.Enum, Value: uint32(0), Enum: signature.Types},
			kparams.ImageSignatureLevel: {Name: kparams.ImageSignatureLevel, Type: kparams.Enum, Value: uint32(0), Enum: signature.Levels},
		},
	}

	var tests2 = []struct {
		filter  string
		matches bool
	}{

		{`image.pid = 1023`, true},
		{`image.name endswith 'mscorlib.dll'`, true},
		{`image.is_dotnet`, true},
	}

	for i, tt := range tests2 {
		f := New(tt.filter, cfg)
		err := f.Compile()
		if err != nil {
			t.Fatal(err)
		}
		matches := f.Run(kevt2)
		if matches != tt.matches {
			t.Errorf("%d. %q image filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}
}

func TestPEFilter(t *testing.T) {
	kevt := &kevent.Kevent{
		PS: &pstypes.PS{
			PE: &pe.PE{
				NumberOfSections: 2,
				NumberOfSymbols:  10,
				EntryPoint:       "20110",
				ImageBase:        "140000000",
				LinkTime:         time.Now(),
				Sections: []pe.Sec{
					{Name: ".text", Size: 132608, Entropy: 6.368381, Md5: "db23dce3911a42e987041d98abd4f7cd"},
					{Name: ".rdata", Size: 35840, Entropy: 5.996976, Md5: "ffa5c960b421ca9887e54966588e97e8"},
				},
				Symbols:          []string{"SelectObject", "GetTextFaceW", "EnumFontsW", "TextOutW", "GetProcessHeap"},
				Imports:          []string{"GDI32.dll", "USER32.dll", "msvcrt.dll", "api-ms-win-core-libraryloader-l1-2-0.dl"},
				VersionResources: map[string]string{"CompanyName": "Microsoft Corporation", "FileDescription": "Notepad", "FileVersion": "10.0.18362.693"},
			},
		},
	}

	var tests = []struct {
		filter  string
		matches bool
	}{

		{`foreach(pe._sections, $section, $section.entropy = 6.368381)`, true},
		{`foreach(pe._sections, $section, $section.entropy > 4.45)`, true},
		{`foreach(pe._sections, $section, $section.name = '.rdata' and $section.entropy < 9.45)`, true},
		{`foreach(pe._sections, $section, $section.size = 132608)`, true},
		{`foreach(pe._sections, $section, $section.md5 = 'ffa5c960b421ca9887e54966588e97e8')`, true},
		{`pe.symbols IN ('GetTextFaceW', 'GetProcessHeap')`, true},
		{`pe.resources[FileDesc] = 'Notepad'`, true},
		{`pe.resources[CompanyName] = 'Microsoft Corporation'`, true},
		{`pe.resources in ('FileDescription:Notepad')`, true},
		{`pe.nsymbols = 10 AND pe.nsections = 2`, true},
		{`pe.nsections > 1`, true},
		{`pe.address.base = '140000000' AND pe.address.entrypoint = '20110'`, true},
	}

	for i, tt := range tests {
		f := New(tt.filter, cfg)
		err := f.Compile()
		if err != nil {
			t.Fatal(err)
		}
		matches := f.Run(kevt)
		if matches != tt.matches {
			t.Errorf("%d. %q pe filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}
}

func TestLazyPEFilter(t *testing.T) {
	kevt := &kevent.Kevent{
		Type: ktypes.LoadImage,
		PS: &pstypes.PS{
			PID: 2312,
			Exe: filepath.Join(os.Getenv("windir"), "notepad.exe"),
		},
		Kparams: kevent.Kparams{
			kparams.FileIsDLL: {Name: kparams.FileIsDLL, Type: kparams.Bool, Value: true},
			kparams.FilePath:  {Name: kparams.FilePath, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\user32.dll"},
		},
	}

	var tests = []struct {
		filter  string
		matches bool
	}{
		{`foreach(pe._sections, $s, $s.entropy > 1.23)`, true},
		{`pe.symbols IN ('GetTextFaceW', 'GetProcessHeap')`, true},
		{`pe.is_dll`, true},
		{`length(pe.imphash) > 0`, true},
		{`pe.is_dotnet`, false},
		{`pe.resources[FileDesc] icontains 'Notepad'`, true},
		{`pe.file.name ~= 'NOTEPAD.EXE'`, true},
		{`pe.nsymbols > 10 AND pe.nsections > 2`, true},
		{`pe.nsections > 1`, true},
		{`length(pe.anomalies) = 0`, true},
		{`pe.is_signed`, true},
		{`pe.is_trusted`, true},
		{`pe.cert.subject icontains 'microsoft'`, true},
		{`pe.cert.issuer icontains 'microsoft'`, true},
		{`length(pe.cert.serial) > 0`, true},
	}

	for i, tt := range tests {
		f := New(tt.filter, cfg)
		err := f.Compile()
		if err != nil {
			t.Fatal(err)
		}
		require.Nil(t, kevt.PS.PE)
		matches := f.Run(kevt)
		if matches != tt.matches {
			t.Errorf("%d. %q pe lazy filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
		require.NotNil(t, kevt.PS.PE)
		kevt.PS.PE = nil
	}
}

func TestMemFilter(t *testing.T) {
	kpars := kevent.Kparams{
		kparams.MemRegionSize:  {Name: kparams.MemRegionSize, Type: kparams.Uint64, Value: uint64(8192)},
		kparams.MemBaseAddress: {Name: kparams.MemBaseAddress, Type: kparams.Address, Value: uint64(1311246336000)},
		kparams.MemAllocType:   {Name: kparams.MemAllocType, Type: kparams.Flags, Value: uint32(0x00001000 | 0x00002000), Flags: kevent.MemAllocationFlags},
		kparams.ProcessID:      {Name: kparams.ProcessID, Type: kparams.Uint32, Value: uint32(345)},
		kparams.MemProtect:     {Name: kparams.MemProtect, Type: kparams.Flags, Value: uint32(0x40), Flags: kevent.MemProtectionFlags},
		kparams.MemProtectMask: {Name: kparams.MemProtectMask, Type: kparams.AnsiString, Value: "RWX"},
		kparams.MemPageType:    {Name: kparams.MemPageType, Type: kparams.Enum, Value: uint32(0x1000000), Enum: processors.MemPageTypes},
	}

	kevt := &kevent.Kevent{
		Type:     ktypes.VirtualAlloc,
		Kparams:  kpars,
		Name:     "VirtualAlloc",
		Category: ktypes.Mem,
		PS: &pstypes.PS{
			Name: "svchost.exe",
			Envs: map[string]string{"ALLUSERSPROFILE": "C:\\ProgramData", "OS": "Windows_NT", "ProgramFiles(x86)": "C:\\Program Files (x86)"},
		},
	}

	var tests = []struct {
		filter  string
		matches bool
	}{

		{`mem.size = 8192`, true},
		{`mem.address = 1311246336000`, true},
		{`mem.type = 'IMAGE'`, true},
		{`mem.size = 8192`, true},
		{`mem.alloc = 'COMMIT|RESERVE'`, true},
		{`mem.protection = 'EXECUTE_READWRITE'`, true},
		{`mem.protection.mask = 'RWX'`, true},
	}

	for i, tt := range tests {
		f := New(tt.filter, cfg)
		err := f.Compile()
		if err != nil {
			t.Fatal(err)
		}
		matches := f.Run(kevt)
		if matches != tt.matches {
			t.Errorf("%d. %q mem filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}
}

func TestDNSFilter(t *testing.T) {
	kevt := &kevent.Kevent{
		Type: ktypes.ReplyDNS,
		Tid:  2484,
		PID:  859,
		PS: &pstypes.PS{
			Name: "cmd.exe",
		},
		Category: ktypes.Net,
		Kparams: kevent.Kparams{
			kparams.DNSName:    {Name: kparams.DNSName, Type: kparams.UnicodeString, Value: "r3.o.lencr.org"},
			kparams.DNSRR:      {Name: kparams.DNSRR, Type: kparams.Enum, Value: uint32(0x0001), Enum: kevent.DNSRecordTypes},
			kparams.DNSOpts:    {Name: kparams.DNSOpts, Type: kparams.Flags64, Value: uint64(0x00006000), Flags: kevent.DNSOptsFlags},
			kparams.DNSRcode:   {Name: kparams.DNSRcode, Type: kparams.Enum, Value: uint32(0), Enum: kevent.DNSResponseCodes},
			kparams.DNSAnswers: {Name: kparams.DNSAnswers, Type: kparams.Slice, Value: []string{"incoming.telemetry.mozilla.org", "a1887.dscq.akamai.net"}},
		},
	}

	var tests = []struct {
		filter  string
		matches bool
	}{

		{`dns.name = 'r3.o.lencr.org'`, true},
		{`dns.rr = 'A'`, true},
		{`dns.options in ('ADDRCONFIG', 'DUAL_ADDR')`, true},
		{`dns.rcode = 'NOERROR'`, true},
		{`dns.answers in ('incoming.telemetry.mozilla.org')`, true},
	}

	for i, tt := range tests {
		f := New(tt.filter, cfg)
		err := f.Compile()
		if err != nil {
			t.Fatal(err)
		}
		matches := f.Run(kevt)
		if matches != tt.matches {
			t.Errorf("%d. %q dns filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}
}

func TestInterpolateFields(t *testing.T) {
	var tests = []struct {
		original     string
		interpolated string
		evts         []*kevent.Kevent
	}{
		{
			original:     "Credential discovery via %ps.name and user %ps.sid",
			interpolated: "Credential discovery via VaultCmd.exe and user LOCAL\\tor",
			evts: []*kevent.Kevent{
				{
					Type:     ktypes.CreateProcess,
					Category: ktypes.Process,
					Name:     "CreateProcess",
					PID:      1023,
					PS: &pstypes.PS{
						Name: "VaultCmd.exe",
						Ppid: 345,
						SID:  "LOCAL\\tor",
					},
				},
			},
		},
		{
			original:     "Credential discovery via %ps.name and pid %kevt.pid",
			interpolated: "Credential discovery via N/A and pid 1023",
			evts: []*kevent.Kevent{
				{
					Type:     ktypes.CreateProcess,
					Category: ktypes.Process,
					Name:     "CreateProcess",
					PID:      1023,
				},
			},
		},
		{
			original: `Detected an attempt by <code>%1.ps.name</code> process to access
and read the memory of the <b>Local Security And Authority Subsystem Service</b>
and subsequently write the <code>%2.file.path</code> dump file to the disk device`,
			interpolated: `Detected an attempt by <code>taskmgr.exe</code> process to access
and read the memory of the <b>Local Security And Authority Subsystem Service</b>
and subsequently write the <code>C:\Users
eo\Temp\lsass.dump</code> dump file to the disk device`,
			evts: []*kevent.Kevent{
				{
					Type:     ktypes.OpenProcess,
					Category: ktypes.Process,
					Name:     "OpenProcess",
					PID:      1023,
					PS: &pstypes.PS{
						Name: "taskmgr.exe",
						Ppid: 345,
						SID:  "LOCAL\\tor",
					},
				},
				{
					Type:     ktypes.WriteFile,
					Category: ktypes.File,
					Name:     "WriteFile",
					PID:      1023,
					Kparams: kevent.Kparams{
						kparams.FilePath: {Name: kparams.FilePath, Type: kparams.UnicodeString, Value: "C:\\Users\neo\\Temp\\lsass.dump"},
					},
					PS: &pstypes.PS{
						Name: "taskmgr.exe",
						Ppid: 345,
						SID:  "LOCAL\\tor",
					},
				},
			},
		},
		{
			original: `Detected an attempt by <code>%ps.name</code> process to access
and read the memory of the <b>Local Security And Authority Subsystem Service</b>
and subsequently write the <code>%2.file.path</code> dump file to the disk device`,
			interpolated: `Detected an attempt by <code>taskmgr.exe</code> process to access
and read the memory of the <b>Local Security And Authority Subsystem Service</b>
and subsequently write the <code>C:\Users
eo\Temp\lsass.dump</code> dump file to the disk device`,
			evts: []*kevent.Kevent{
				{
					Type:     ktypes.OpenProcess,
					Category: ktypes.Process,
					Name:     "OpenProcess",
					PID:      1023,
					PS: &pstypes.PS{
						Name: "taskmgr.exe",
						Ppid: 345,
						SID:  "LOCAL\\tor",
					},
				},
				{
					Type:     ktypes.WriteFile,
					Category: ktypes.File,
					Name:     "WriteFile",
					PID:      1023,
					Kparams: kevent.Kparams{
						kparams.FilePath: {Name: kparams.FilePath, Type: kparams.UnicodeString, Value: "C:\\Users\neo\\Temp\\lsass.dump"},
					},
					PS: &pstypes.PS{
						Name: "taskmgr.exe",
						Ppid: 345,
						SID:  "LOCAL\\tor",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		s := InterpolateFields(tt.original, tt.evts)
		if tt.interpolated != s {
			t.Errorf("expected %s interpolated string but got %s", tt.interpolated, s)
		}
	}
}

func BenchmarkFilterRun(b *testing.B) {
	b.ReportAllocs()
	f := New(`ps.name = 'mimikatz.exe' or ps.name contains 'svc'`, cfg)
	require.NoError(b, f.Compile())

	kpars := kevent.Kparams{
		kparams.Cmdline:         {Name: kparams.Cmdline, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\svchost.exe -k RPCSS"},
		kparams.ProcessName:     {Name: kparams.ProcessName, Type: kparams.AnsiString, Value: "svchost.exe"},
		kparams.ProcessID:       {Name: kparams.ProcessID, Type: kparams.Uint32, Value: uint32(1234)},
		kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.Uint32, Value: uint32(345)},
	}

	kevt := &kevent.Kevent{
		Type:    ktypes.CreateProcess,
		Kparams: kpars,
		Name:    "CreateProcess",
	}

	for i := 0; i < b.N; i++ {
		f.Run(kevt)
	}
}

func getNtdllAddress(pid uint32) uintptr {
	var moduleHandles [1024]windows.Handle
	var cbNeeded uint32
	proc, err := windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false, pid)
	if err != nil {
		return 0
	}
	if err := windows.EnumProcessModules(proc, &moduleHandles[0], 1024, &cbNeeded); err != nil {
		return 0
	}
	moduleHandle := moduleHandles[1]
	var moduleInfo windows.ModuleInfo
	if err := windows.GetModuleInformation(proc, moduleHandle, &moduleInfo, uint32(unsafe.Sizeof(moduleInfo))); err != nil {
		return 0
	}
	return moduleInfo.BaseOfDll
}

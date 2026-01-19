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
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"github.com/rabbitstack/fibratus/internal/etw/processors"
	"github.com/rabbitstack/fibratus/internal/evasion"
	"github.com/rabbitstack/fibratus/pkg/callstack"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/rabbitstack/fibratus/pkg/filter/ql"
	"github.com/rabbitstack/fibratus/pkg/fs"
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
)

var cfg = &config.Config{
	EventSource: config.EventSourceConfig{
		EnableHandleEvents:     true,
		EnableNetEvents:        true,
		EnableRegistryEvents:   true,
		EnableFileIOEvents:     true,
		EnableImageEvents:      true,
		EnableThreadEvents:     true,
		EnableMemEvents:        true,
		EnableDNSEvents:        true,
		EnableThreadpoolEvents: true,
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
|evt.name = 'CreateProcess'| by ps.exe
|evt.name = 'CreateFile' and file.operation = 'create'| by file.name
`, cfg)
	require.NoError(t, f.Compile())
	require.NotNil(t, f.GetSequence())
	assert.Len(t, f.GetSequence().Expressions, 2)
	assert.NotNil(t, f.GetSequence().Expressions[0].By)
	assert.True(t, len(f.GetStringFields()) > 0)
}

func TestSeqFilterInvalidBoundRefs(t *testing.T) {
	f := New(`sequence
|evt.name = 'CreateProcess'| as e1
|evt.name = 'CreateFile' and file.name = $e.ps.exe |
`, cfg)
	require.Error(t, f.Compile())
	f1 := New(`sequence
|evt.name = 'CreateProcess'| as e1
|evt.name = 'CreateFile' and file.name = $e1.ps.exe |
`, cfg)
	require.NoError(t, f1.Compile())
}

func TestStringFields(t *testing.T) {
	f := New(`ps.name = 'cmd.exe' and evt.name = 'CreateProcess' or evt.name in ('TerminateProcess', 'CreateFile')`, cfg)
	require.NoError(t, f.Compile())
	assert.Len(t, f.GetStringFields(), 2)
	assert.Len(t, f.GetStringFields()[fields.EvtName], 3)
	assert.Len(t, f.GetStringFields()[fields.PsName], 1)
}

func TestMakeSequenceLinkID(t *testing.T) {
	var tests = []struct {
		valuer  ql.MapValuer
		seqLink *ql.SequenceLink
		id      any
	}{
		{ql.MapValuer{
			"ps.uuid": uint64(123232454234232132),
			"ps.exe":  "C:\\Windows\\System32\\cmd.exe"},
			&ql.SequenceLink{Fields: []*ql.FieldLiteral{{Value: "ps.exe"}, {Value: "ps.uuid"}}},
			"433a5c57696e646f77735c53797374656d33325c636d642e65786544556ea343cfb501",
		},
		{ql.MapValuer{
			"ps.uuid":        uint64(123232454234232132),
			"module.address": uint64(0xfff32343)},
			&ql.SequenceLink{Fields: []*ql.FieldLiteral{{Value: "ps.uuid"}, {Value: "module.address"}}},
			"44556ea343cfb5014323f3ff00000000",
		},
		{ql.MapValuer{
			"ps.uuid": uint64(123232454234232132),
			"ps.exe":  "C:\\Windows\\System32\\cmd.exe"},
			&ql.SequenceLink{Fields: []*ql.FieldLiteral{{Value: "ps.exe"}}},
			"C:\\Windows\\System32\\cmd.exe",
		},
		{ql.MapValuer{
			"ps.uuid": uint64(123232454234232132),
			"ps.exe":  "C:\\Windows\\System32\\cmd.exe"},
			&ql.SequenceLink{Fields: []*ql.FieldLiteral{{Value: "ps.uuid"}}},
			uint64(123232454234232132),
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%v", tt.valuer), func(t *testing.T) {
			assert.Equal(t, tt.id, makeSequenceLinkID(tt.valuer, tt.seqLink))
		})
	}
}

func TestProcFilter(t *testing.T) {
	parent := &pstypes.PS{
		Name:     "svchost.exe",
		Cmdline:  "C:\\Windows\\system32\\svchost.exe -k RPCSS",
		Username: "SYSTEM",
		Domain:   "NT AUTHORITY",
		SID:      "S-1-5-18",
		PID:      5042,
		Parent: &pstypes.PS{
			Name: "services.exe",
			SID:  "S-1-5-8",
			PID:  2034,
			Parent: &pstypes.PS{
				Name: "csrss.exe",
			},
		},
		IsWOW64:             false,
		IsProtected:         true,
		IsPackaged:          false,
		TokenIntegrityLevel: "SYSTEM",
		IsTokenElevated:     false,
		TokenElevationType:  "DEFAULT",
	}

	evt := &event.Event{
		Type:     event.CreateProcess,
		Category: event.Process,
		Params: event.Params{
			params.Cmdline:                    {Name: params.Cmdline, Type: params.UnicodeString, Value: "C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p -s LSM"},
			params.ProcessName:                {Name: params.ProcessName, Type: params.AnsiString, Value: "svchost.exe"},
			params.ProcessID:                  {Name: params.ProcessID, Type: params.PID, Value: uint32(1234)},
			params.ProcessParentID:            {Name: params.ProcessParentID, Type: params.PID, Value: uint32(345)},
			params.UserSID:                    {Name: params.UserSID, Type: params.WbemSID, Value: []byte{224, 8, 226, 31, 15, 167, 255, 255, 0, 0, 0, 0, 15, 167, 255, 255, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}},
			params.Username:                   {Name: params.Username, Type: params.UnicodeString, Value: "SYSTEM"},
			params.Domain:                     {Name: params.Domain, Type: params.UnicodeString, Value: "NT AUTHORITY"},
			params.ProcessFlags:               {Name: params.ProcessFlags, Type: params.Flags, Value: uint32(0x000000E)},
			params.ProcessTokenIntegrityLevel: {Name: params.ProcessTokenIntegrityLevel, Type: params.AnsiString, Value: "SYSTEM"},
			params.ProcessTokenIsElevated:     {Name: params.ProcessTokenIsElevated, Type: params.Bool, Value: true},
			params.ProcessTokenElevationType:  {Name: params.ProcessTokenElevationType, Type: params.AnsiString, Value: "DEFAULT"},
		},
		Name: "CreateProcess",
		PID:  1234,
		PS: &pstypes.PS{
			Name:     "svchost.exe",
			Cmdline:  "C:\\Windows\\System32\\svchost.exe -k DcomLaunch -p -s LSM",
			Parent:   parent,
			PID:      1234,
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
			IsProtected:         false,
			IsPackaged:          true,
			IsWOW64:             false,
			TokenIntegrityLevel: "SYSTEM",
			IsTokenElevated:     true,
			TokenElevationType:  "DEFAULT",
		},
	}
	evt.Timestamp, _ = time.Parse(time.RFC3339, "2011-05-03T15:04:05.323Z")

	evt1 := &event.Event{
		Type:     event.OpenProcess,
		Category: event.Process,
		Params: event.Params{
			params.DesiredAccess: {Name: params.DesiredAccess, Type: params.Flags, Value: uint32(0x1400), Flags: event.PsAccessRightFlags},
		},
		Name: "OpenProcess",
		PID:  1023,
		PS: &pstypes.PS{
			Name:   "svchost.exe",
			Parent: parent,
			Ppid:   345,
			Envs:   map[string]string{"ALLUSERSPROFILE": "C:\\ProgramData", "OS": "Windows_NT", "ProgramFiles(x86)": "C:\\Program Files (x86)"},
			Modules: []pstypes.Module{
				{Name: "C:\\Windows\\System32\\kernel32.dll", Size: 12354, Checksum: 23123343, BaseAddress: va.Address(4294066175), DefaultBaseAddress: va.Address(4293993725)},
				{Name: "C:\\Windows\\System32\\user32.dll", Size: 212354, Checksum: 33123343, BaseAddress: va.Address(4277288959), DefaultBaseAddress: va.Address(4293993725)},
			},
		},
	}

	evt2 := &event.Event{
		Type:     event.OpenProcess,
		Category: event.Process,
		Params: event.Params{
			params.DesiredAccess: {Name: params.DesiredAccess, Type: params.Flags, Value: uint32(0x1400), Flags: event.PsAccessRightFlags},
		},
		Name: "OpenProcess",
		PID:  1023,
	}

	var tests = []struct {
		filter  string
		matches bool
	}{

		{`ps.name = 'svchost.exe'`, true},
		{`ps.name = 'svchot.exe'`, false},
		{`ps.name = 'csrss.exe' or ps.name contains 'svc'`, true},
		{`ps.name ~= 'SVCHOST.exe'`, true},
		{`ps.parent.cmdline = 'C:\\Windows\\system32\\svchost.exe -k RPCSS'`, true},
		{`ps.cmdline = 'C:\\Windows\\System32\\svchost.exe -k DcomLaunch -p -s LSM'`, true},
		{`ps.username = 'SYSTEM'`, true},
		{`ps.domain = 'NT AUTHORITY'`, true},
		{`ps.sid = 'S-1-5-18'`, true},
		{`ps.pid = 1234`, true},
		{`ps.parent.sid = 'S-1-5-18'`, true},
		{`ps.uuid > 0`, true},
		{`ps.parent.name = 'svchost.exe'`, true},
		{`ps.parent.pid = 5042`, true},
		{`ps.parent.username = 'SYSTEM'`, true},
		{`ps.parent.domain = 'NT AUTHORITY'`, true},
		{`ps.envs[ALLUSERSPROFILE] = 'C:\\ProgramData'`, true},
		{`ps.envs[ALLUSER] = 'C:\\ProgramData'`, true},
		{`ps.envs[ProgramFiles] = 'C:\\Program Files (x86)'`, true},
		{`ps.envs[windir] = 'C:\\WINDOWS'`, false},
		{`ps.envs in ('ALLUSERSPROFILE:C:\\ProgramData')`, true},
		{`foreach(ps.envs, $env, substr($env, 0, indexof($env, ':')) = 'OS')`, true},

		{`ps.is_wow64`, false},
		{`ps.is_packaged`, true},
		{`ps.is_protected`, false},
		{`ps.parent.is_wow64`, false},
		{`ps.parent.is_packaged`, false},
		{`ps.parent.is_protected`, true},
		{`ps.token.integrity_level = 'SYSTEM'`, true},
		{`ps.token.is_elevated = true`, true},
		{`ps.token.elevation_type = 'DEFAULT'`, true},
		{`ps.token.integrity_level = 'SYSTEM'`, true},
		{`ps.token.is_elevated = true`, true},
		{`ps.parent.token.integrity_level = 'SYSTEM'`, true},
		{`ps.parent.token.is_elevated = false`, true},
		{`ps.parent.token.elevation_type = 'DEFAULT'`, true},

		{`evt.name = 'CreateProcess' and ps.name contains 'svchost'`, true},

		{`ps.modules IN ('kernel32.dll')`, true},
		{`evt.name = 'CreateProcess' and evt.pid != ps.ppid`, true},
		{`ps.parent.name = 'svchost.exe'`, true},

		{`ps.ancestor[0] = 'svchost.exe'`, true},
		{`ps.ancestor[0] = 'csrss.exe'`, false},
		{`ps.ancestor[1] = 'services.exe'`, true},
		{`ps.ancestor[2] = 'csrss.exe'`, true},
		{`ps.ancestor[3] = ''`, true},
		{`ps.ancestor intersects ('csrss.exe', 'services.exe', 'svchost.exe')`, true},

		{`foreach(ps._ancestors, $proc, $proc.name in ('csrss.exe', 'services.exe', 'System'))`, true},
		{`foreach(ps._ancestors, $proc, $proc.name in ('csrss.exe', 'services.exe', 'System') and ps.is_packaged, ps.is_packaged)`, true},
		{`foreach(ps._ancestors, $proc, $proc.name not in ('svchost.exe', 'WmiPrvSE.exe'))`, true},
		{`foreach(ps._ancestors, $proc, $proc.sid = 'S-1-5-8'))`, true},
		{`foreach(ps._ancestors, $proc, $proc.name endswith 'ices.exe'))`, true},
		{`foreach(ps._ancestors, $proc, $proc.pid in (2034, 343) and $proc.name = 'services.exe')`, true},
		{`foreach(ps._ancestors, $proc, $proc.username = 'SYSTEM')`, true},
		{`foreach(ps._ancestors, $proc, $proc.domain = 'NT AUTHORITY')`, true},
		{`foreach(ps._ancestors, $proc, $proc.username = upper('system'))`, true},
		{`foreach(ps._ancestors, $proc, $proc.token.integrity_level = 'SYSTEM' and $proc.token.is_elevated = false and $proc.token.elevation_type = 'DEFAULT')`, true},

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
	psnap.On("FindAndPut", uint32(1234)).Return(parent)

	for i, tt := range tests {
		f := New(tt.filter, cfg, WithPSnapshotter(psnap))
		err := f.Compile()
		if err != nil {
			t.Fatal(err)
		}
		matches := f.Run(evt)
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
		matches := f.Run(evt1)
		if matches != tt.matches {
			t.Errorf("%d. %q ps filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}

	var tests2 = []struct {
		filter  string
		matches bool
	}{

		{`ps.exe = ''`, true},
	}

	for i, tt := range tests2 {
		f := New(tt.filter, cfg)
		err := f.Compile()
		if err != nil {
			t.Fatal(err)
		}
		matches := f.Run(evt2)
		if matches != tt.matches {
			t.Errorf("%d. %q ps filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}
}

func TestThreadFilter(t *testing.T) {
	pars := event.Params{
		params.ProcessID:          {Name: params.ProcessID, Type: params.PID, Value: uint32(os.Getpid())},
		params.ThreadID:           {Name: params.ThreadID, Type: params.TID, Value: uint32(3453)},
		params.BasePrio:           {Name: params.BasePrio, Type: params.Uint8, Value: uint8(13)},
		params.StartAddress:       {Name: params.StartAddress, Type: params.Address, Value: uint64(140729524944768)},
		params.TEB:                {Name: params.TEB, Type: params.Address, Value: uint64(614994620416)},
		params.IOPrio:             {Name: params.IOPrio, Type: params.Uint8, Value: uint8(2)},
		params.KstackBase:         {Name: params.KstackBase, Type: params.Address, Value: uint64(18446677035730165760)},
		params.KstackLimit:        {Name: params.KstackLimit, Type: params.Address, Value: uint64(18446677035730137088)},
		params.PagePrio:           {Name: params.PagePrio, Type: params.Uint8, Value: uint8(5)},
		params.UstackBase:         {Name: params.UstackBase, Type: params.Address, Value: uint64(86376448)},
		params.UstackLimit:        {Name: params.UstackLimit, Type: params.Address, Value: uint64(86372352)},
		params.StartAddressSymbol: {Name: params.StartAddressSymbol, Type: params.UnicodeString, Value: "LoadImage"},
		params.StartAddressModule: {Name: params.StartAddressModule, Type: params.UnicodeString, Value: "C:\\Windows\\System32\\kernel32.dll"},
	}
	evt := &event.Event{
		Type:     event.CreateThread,
		Params:   pars,
		Name:     "CreateThread",
		PID:      windows.GetCurrentProcessId(),
		Category: event.Thread,
		PS: &pstypes.PS{
			Name: "svchost.exe",
			Envs: map[string]string{"ALLUSERSPROFILE": "C:\\ProgramData", "OS": "Windows_NT", "ProgramFiles(x86)": "C:\\Program Files (x86)"},
			Modules: []pstypes.Module{
				{Name: "C:\\Windows\\System32\\kernel32.dll", Size: 2312354, Checksum: 23123343, BaseAddress: va.Address(0x7ffb5c1d0396), DefaultBaseAddress: va.Address(0x7ffb5c1d0396)},
				{Name: "C:\\Windows\\System32\\user32.dll", Size: 32212354, Checksum: 33123343, BaseAddress: va.Address(0x7ffb313953b2), DefaultBaseAddress: va.Address(0x7ffb313953b2)},
				{Name: "C:\\Program Files\\JetBrains\\GoLand 2021.2.3\\jbr\\bin\\java.dll", Size: 32212354, Checksum: 33123343, BaseAddress: va.Address(0x7ffb3138592e), DefaultBaseAddress: va.Address(0x7ffb3138592e)},
			},
		},
	}

	// append the module signature
	cert := &sys.Cert{Subject: "US, Washington, Redmond, Microsoft Corporation, Microsoft Windows", Issuer: "US, Washington, Redmond, Microsoft Corporation, Microsoft Windows Production PCA 2011"}
	signature.GetSignatures().PutSignature(0x7ffb3138592e, &signature.Signature{Filename: "C:\\Program Files\\JetBrains\\GoLand 2021.2.3\\jbr\\bin\\java.dll", Level: 4, Type: 1, Cert: cert})

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

	evt.Callstack.Init(8)
	evt.Callstack.PushFrame(callstack.Frame{PID: evt.PID, Addr: 0x2638e59e0a5, Offset: 0, Symbol: "?", Module: "unbacked"})
	evt.Callstack.PushFrame(callstack.Frame{PID: evt.PID, Addr: va.Address(base), Offset: 0, Symbol: "?", Module: "unbacked"})
	evt.Callstack.PushFrame(callstack.Frame{PID: evt.PID, Addr: 0x7ffb313853b2, Offset: 0x10a, Symbol: "Java_java_lang_ProcessImpl_create", Module: "C:\\Program Files\\JetBrains\\GoLand 2021.2.3\\jbr\\bin\\java.dll"})
	evt.Callstack.PushFrame(callstack.Frame{PID: evt.PID, Addr: 0x7ffb3138592e, ModuleAddress: 0x7ffb3138592e, Offset: 0x3a2, Symbol: "Java_java_lang_ProcessImpl_waitForTimeoutInterruptibly", Module: "C:\\Program Files\\JetBrains\\GoLand 2021.2.3\\jbr\\bin\\java.dll"})
	evt.Callstack.PushFrame(callstack.Frame{PID: evt.PID, Addr: 0x7ffb5d8e61f4, Offset: 0x54, Symbol: "CreateProcessW", Module: "C:\\WINDOWS\\System32\\KERNEL32.DLL"})
	evt.Callstack.PushFrame(callstack.Frame{PID: evt.PID, Addr: 0x7ffb5c1d0396, Offset: 0x66, Symbol: "CreateProcessW", Module: "C:\\WINDOWS\\System32\\KERNELBASE.dll"})
	evt.Callstack.PushFrame(callstack.Frame{PID: evt.PID, Addr: 0xfffff8072ebc1f6f, Offset: 0x4ef, Symbol: "FltRequestFileInfoOnCreateCompletion", Module: "C:\\WINDOWS\\System32\\drivers\\FLTMGR.SYS"})
	evt.Callstack.PushFrame(callstack.Frame{PID: evt.PID, Addr: 0xfffff8072eb8961b, Offset: 0x20cb, Symbol: "FltGetStreamContext", Module: "C:\\WINDOWS\\System32\\drivers\\FLTMGR.SYS"})

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
		{`thread.start_address.symbol = 'LoadImage'`, true},
		{`thread.start_address.module = 'C:\\Windows\\System32\\kernel32.dll'`, true},
		{`thread.callstack.summary = 'KERNELBASE.dll|KERNEL32.DLL|java.dll|unbacked'`, true},
		{`thread.callstack.detail icontains 'C:\\WINDOWS\\System32\\KERNELBASE.dll!CreateProcessW+0x66'`, true},
		{`thread.callstack.modules in ('C:\\WINDOWS\\System32\\KERNELBASE.dll', 'C:\\Program Files\\JetBrains\\GoLand 2021.2.3\\jbr\\bin\\java.dll')`, true},
		{`thread.callstack.modules[5] = 'C:\\WINDOWS\\System32\\KERNELBASE.dll'`, true},
		{`thread.callstack.modules[7] = 'C:\\WINDOWS\\System32\\drivers\\FLTMGR.SYS'`, true},
		{`thread.callstack.modules[8] = ''`, true},
		{`thread.callstack.symbols imatches ('KERNELBASE.dll!CreateProcess*', 'Java_java_lang_ProcessImpl_create')`, true},
		{`thread.callstack.symbols[2] = 'Java_java_lang_ProcessImpl_create'`, true},
		{`thread.callstack.symbols[8] = ''`, true},
		{`thread.callstack.protections in ('RWX')`, true},
		{`thread.callstack.allocation_sizes > 0`, false},
		{`length(thread.callstack.callsite_leading_assembly) > 0`, true},
		{`thread.callstack.callsite_trailing_assembly matches ('*mov r10, rcx|mov eax, 0x*|syscall*')`, true},
		{`thread.callstack.is_unbacked`, true},
		{`thread.callstack.addresses intersects ('7ffb5d8e61f4', 'fffff8072eb8961b')`, true},
		{`thread.callstack.final_user_module.name = 'java.dll'`, true},
		{`thread.callstack.final_user_module.path = 'C:\\Program Files\\JetBrains\\GoLand 2021.2.3\\jbr\\bin\\java.dll'`, true},
		{`thread.callstack.final_user_symbol.name = 'Java_java_lang_ProcessImpl_waitForTimeoutInterruptibly'`, true},
		{`thread.callstack.final_kernel_module.name = 'FLTMGR.SYS'`, true},
		{`thread.callstack.final_kernel_module.path = 'C:\\WINDOWS\\System32\\drivers\\FLTMGR.SYS'`, true},
		{`thread.callstack.final_kernel_symbol.name = 'FltGetStreamContext'`, true},
		{`thread.callstack.final_user_module.signature.is_signed = true`, true},
		{`thread.callstack.final_user_module.signature.is_trusted = true`, true},
		{`thread.callstack.final_user_module.signature.cert.issuer imatches '*Microsoft Corporation*'`, true},
		{`thread.callstack.final_user_module.signature.cert.subject imatches '*Microsoft Windows*'`, true},

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
		{`foreach(thread._callstack, $frame, $frame.module.signature.is_signed and $frame.module.signature.is_trusted)`, true},
		{`foreach(thread._callstack, $frame, $frame.module.signature.cert.issuer imatches '*Microsoft Corporation*')`, true},
		{`foreach(thread._callstack, $frame, $frame.module.signature.cert.subject imatches '*Microsoft Windows*')`, true},
	}

	for i, tt := range tests {
		f := New(tt.filter, cfg)
		err := f.Compile()
		if err != nil {
			t.Fatal(err)
		}
		matches := f.Run(evt)
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

	evt.PID = pi.ProcessId

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

	evt.Callstack[0] = callstack.Frame{PID: evt.PID, Addr: va.Address(ntdll), Offset: 0, Symbol: "?", Module: "C:\\Windows\\System32\\ntdll.dll"}

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
		matches := f.Run(evt)
		if matches != tt.matches {
			t.Errorf("%d. %q thread filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}
}

func TestFileFilter(t *testing.T) {
	evt := &event.Event{
		Type:        event.CreateFile,
		Tid:         2484,
		PID:         859,
		CPU:         1,
		Seq:         2,
		Name:        "CreateFile",
		Category:    event.File,
		Host:        "archrabbit",
		Description: "Creates or opens a new file, directory, I/O device, pipe, console",
		Params: event.Params{
			params.FileObject:    {Name: params.FileObject, Type: params.Uint64, Value: uint64(12456738026482168384)},
			params.FilePath:      {Name: params.FilePath, Type: params.UnicodeString, Value: "C:\\Windows\\system32\\user32.dll"},
			params.FileType:      {Name: params.FileType, Type: params.AnsiString, Value: "file"},
			params.FileOperation: {Name: params.FileOperation, Type: params.AnsiString, Value: "open"},
		},
		Metadata: map[event.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
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
		{`file.path.stem = 'C:\\Windows\\system32\\user32'`, true},
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
		matches := f.Run(evt)
		if matches != tt.matches {
			t.Errorf("%d. %q file filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}
}

func TestFileInfoFilter(t *testing.T) {
	var tests = []struct {
		f       string
		e       *event.Event
		matches bool
	}{
		{
			`file.info_class = 'Allocation'`,
			&event.Event{
				Category: event.File,
				Type:     event.SetFileInformation,
				Name:     "SetFileInformation",
				Params: event.Params{
					params.FileInfoClass: {Name: params.FileInfoClass, Type: params.Enum, Value: fs.AllocationClass, Enum: fs.FileInfoClasses},
				},
			},
			true,
		},
		{
			`file.info.allocation_size = 64500`,
			&event.Event{
				Category: event.File,
				Type:     event.SetFileInformation,
				Name:     "SetFileInformation",
				Params: event.Params{
					params.FileInfoClass: {Name: params.FileInfoClass, Type: params.Enum, Value: fs.AllocationClass, Enum: fs.FileInfoClasses},
					params.FileExtraInfo: {Name: params.FileExtraInfo, Type: params.Uint64, Value: uint64(64500)},
				},
			},
			true,
		},
		{
			`file.info.eof_size = 64500`,
			&event.Event{
				Category: event.File,
				Type:     event.SetFileInformation,
				Name:     "SetFileInformation",
				Params: event.Params{
					params.FileInfoClass: {Name: params.FileInfoClass, Type: params.Enum, Value: fs.EOFClass, Enum: fs.FileInfoClasses},
					params.FileExtraInfo: {Name: params.FileExtraInfo, Type: params.Uint64, Value: uint64(64500)},
				},
			},
			true,
		},
		{
			`file.info.eof_size = 64500`,
			&event.Event{
				Category: event.File,
				Type:     event.SetFileInformation,
				Name:     "SetFileInformation",
				Params: event.Params{
					params.FileInfoClass: {Name: params.FileInfoClass, Type: params.Enum, Value: fs.DispositionClass, Enum: fs.FileInfoClasses},
					params.FileExtraInfo: {Name: params.FileExtraInfo, Type: params.Uint64, Value: uint64(1)},
				},
			},
			false,
		},
		{
			`file.info.is_disposition_delete_file = true`,
			&event.Event{
				Category: event.File,
				Type:     event.DeleteFile,
				Name:     "DeleteFile",
				Params: event.Params{
					params.FileInfoClass: {Name: params.FileInfoClass, Type: params.Enum, Value: fs.DispositionClass, Enum: fs.FileInfoClasses},
					params.FileExtraInfo: {Name: params.FileExtraInfo, Type: params.Uint64, Value: uint64(1)},
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

func TestEventFilter(t *testing.T) {
	evt := &event.Event{
		Type:        event.CreateFile,
		Tid:         2484,
		PID:         859,
		CPU:         1,
		Seq:         2,
		Name:        "CreateFile",
		Category:    event.File,
		Host:        "archrabbit",
		Description: "Creates or opens a new file, directory, I/O device, pipe, console",
		Evasions:    uint32(evasion.IndirectSyscall),
		Params: event.Params{
			params.ProcessID:     {Name: params.ProcessID, Type: params.PID, Value: uint32(3434)},
			params.FileObject:    {Name: params.FileObject, Type: params.Uint64, Value: uint64(12456738026482168384)},
			params.FilePath:      {Name: params.FilePath, Type: params.UnicodeString, Value: "\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll"},
			params.FileType:      {Name: params.FileType, Type: params.AnsiString, Value: "file"},
			params.FileOperation: {Name: params.FileOperation, Type: params.AnsiString, Value: "open"},
		},
		Metadata: map[event.MetadataKey]any{"foo": "bar", "fooz": "barz"},
	}

	evt.Timestamp, _ = time.Parse(time.RFC3339, "2011-05-03T15:04:05.323Z")

	var tests = []struct {
		filter  string
		matches bool
	}{

		{`evt.seq = 2`, true},
		{`evt.pid = 859`, true},
		{`evt.tid = 2484`, true},
		{`evt.cpu = 1`, true},
		{`evt.name = 'CreateFile'`, true},
		{`evt.category = 'file'`, true},
		{`evt.host = 'archrabbit'`, true},
		{`evt.nparams = 5`, true},
		{`evt.arg[file_path] = '\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll'`, true},
		{`evt.arg[type] = 'file'`, true},
		{`evt.arg[pid] = 3434`, true},
		{`evt.is_direct_syscall = false`, true},
		{`evt.is_indirect_syscall`, true},

		{`evt.desc contains 'Creates or opens a new file'`, true},

		{`evt.date.d = 3 AND evt.date.m = 5 AND evt.time.s = 5 AND evt.time.m = 4 and evt.time.h = 15`, true},
		{`evt.time = '15:04:05'`, true},
		{`concat(evt.name, evt.host, evt.nparams) = 'CreateFilearchrabbit5'`, true},
		{`ltrim(evt.host, 'arch') = 'rabbit'`, true},
		{`concat(ltrim(evt.name, 'Create'), evt.host) = 'Filearchrabbit'`, true},
		{`lower(rtrim(evt.name, 'File')) = 'create'`, true},
		{`upper(rtrim(evt.name, 'File')) = 'CREATE'`, true},
		{`replace(evt.host, 'rabbit', '_bunny') = 'arch_bunny'`, true},
		{`replace(evt.host, 'rabbit', '_bunny', '_bunny', 'bunny') = 'archbunny'`, true},
		{`split(file.path, '\\') IN ('windows', 'system32')`, true},
		{`length(file.path) = 51`, true},
		{`indexof(file.path, '\\') = 0`, true},
		{`indexof(file.path, '\\', 'last') = 40`, true},
		{`indexof(file.path, 'h2', 'any') = 22`, true},
		{`substr(file.path, indexof(file.path, '\\'), indexof(file.path, '\\Hard')) = '\\Device'`, true},
		{`substr(evt.desc, indexof(evt.desc, '\\'), indexof(evt.desc, 'NOT')) = 'Creates or opens a new file, directory, I/O device, pipe, console'`, true},
		{`entropy(file.path) > 120`, true},
		{`regex(file.path, '\\\\Device\\\\HarddiskVolume[2-9]+\\\\.*')`, true},
	}

	for i, tt := range tests {
		f := New(tt.filter, cfg)
		err := f.Compile()
		if err != nil {
			t.Fatal(err)
		}
		matches := f.Run(evt)
		if matches != tt.matches {
			t.Errorf("%d. %q evt filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}
}

func TestNetFilter(t *testing.T) {
	evt := &event.Event{
		Type: event.SendTCPv4,
		Tid:  2484,
		PID:  859,
		PS: &pstypes.PS{
			Name: "cmd.exe",
		},
		Category: event.Net,
		Params: event.Params{
			params.NetDport: {Name: params.NetDport, Type: params.Uint16, Value: uint16(443)},
			params.NetSport: {Name: params.NetSport, Type: params.Uint16, Value: uint16(43123)},
			params.NetSIP:   {Name: params.NetSIP, Type: params.IPv4, Value: net.ParseIP("127.0.0.1")},
			params.NetDIP:   {Name: params.NetDIP, Type: params.IPv4, Value: net.ParseIP("216.58.201.174")},
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
		{`cidr_contains(net.dip, '216.58.201.1/24', '216.58.201.10/24') = true and evt.pid = 859`, true},
		{`evt.name not in ('CreateProcess', 'Connect') and cidr_contains(net.dip, '216.58.201.1/24') = true`, true},
	}

	for i, tt := range tests {
		f := New(tt.filter, cfg)
		err := f.Compile()
		if err != nil {
			t.Fatal(err)
		}
		matches := f.Run(evt)
		if matches != tt.matches {
			t.Errorf("%d. %q net filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}

	evt1 := &event.Event{
		Type: event.SendTCPv4,
		Tid:  2484,
		PID:  859,
		PS: &pstypes.PS{
			Name: "cmd.exe",
		},
		Category: event.Net,
		Params: event.Params{
			params.NetDport: {Name: params.NetDport, Type: params.Uint16, Value: uint16(53)},
			params.NetSport: {Name: params.NetSport, Type: params.Uint16, Value: uint16(43123)},
			params.NetSIP:   {Name: params.NetSIP, Type: params.IPv4, Value: net.ParseIP("127.0.0.1")},
			params.NetDIP:   {Name: params.NetDIP, Type: params.IPv4, Value: net.ParseIP("8.8.8.8")},
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
		matches := f.Run(evt1)
		if matches != tt.matches {
			t.Errorf("%d. %q net filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}
}

func TestRegistryFilter(t *testing.T) {
	evt := &event.Event{
		Type:     event.RegSetValue,
		Tid:      2484,
		PID:      859,
		Category: event.Registry,
		Params: event.Params{
			params.RegPath:      {Name: params.RegPath, Type: params.UnicodeString, Value: `HKEY_LOCAL_MACHINE\SYSTEM\Setup\Pid`},
			params.RegData:      {Name: params.RegData, Type: params.Uint32, Value: uint32(10234)},
			params.RegValueType: {Name: params.RegValueType, Type: params.AnsiString, Value: "DWORD"},
			params.NTStatus:     {Name: params.NTStatus, Type: params.AnsiString, Value: "success"},
			params.RegKeyHandle: {Name: params.RegKeyHandle, Type: params.Address, Value: uint64(18446666033449935464)},
		},
	}

	var tests = []struct {
		filter  string
		matches bool
	}{

		{`registry.status startswith ('key not', 'succ')`, true},
		{`registry.path = 'HKEY_LOCAL_MACHINE\\SYSTEM\\Setup\\Pid'`, true},
		{`registry.key.name icontains ('Setup', 'setup')`, true},
		{`registry.value = 'Pid'`, true},
		{`registry.value.type in ('DWORD', 'QWORD')`, true},
		{`registry.data = '10234'`, true},
		{`MD5(registry.path) = 'eab870b2a516206575d2ffa2b98d8af5'`, true},
	}

	for i, tt := range tests {
		f := New(tt.filter, cfg)
		err := f.Compile()
		if err != nil {
			t.Fatal(err)
		}
		matches := f.Run(evt)
		if matches != tt.matches {
			t.Errorf("%d. %q registry filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}
}

func TestImageFilter(t *testing.T) {
	e1 := &event.Event{
		Type:     event.LoadImage,
		Category: event.Image,
		Params: event.Params{
			params.ImagePath:           {Name: params.ImagePath, Type: params.UnicodeString, Value: filepath.Join(os.Getenv("windir"), "System32", "kernel32.dll")},
			params.ProcessID:           {Name: params.ProcessID, Type: params.PID, Value: uint32(1023)},
			params.ImageCheckSum:       {Name: params.ImageCheckSum, Type: params.Uint32, Value: uint32(2323432)},
			params.ImageBase:           {Name: params.ImageBase, Type: params.Address, Value: uint64(0x7ffb313833a3)},
			params.ImageSignatureType:  {Name: params.ImageSignatureType, Type: params.Enum, Value: uint32(1), Enum: signature.Types},
			params.ImageSignatureLevel: {Name: params.ImageSignatureLevel, Type: params.Enum, Value: uint32(4), Enum: signature.Levels},
			params.FileIsDotnet:        {Name: params.FileIsDotnet, Type: params.Bool, Value: false},
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
		{`image.path.stem endswith 'System32\\kernel32'`, true},
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
		matches := f.Run(e1)
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
	e2 := &event.Event{
		Type:     event.LoadImage,
		Category: event.Image,
		Params: event.Params{
			params.ImagePath:           {Name: params.ImagePath, Type: params.UnicodeString, Value: filepath.Join(os.Getenv("windir"), "System32", "kernel32.dll")},
			params.ProcessID:           {Name: params.ProcessID, Type: params.PID, Value: uint32(1023)},
			params.ImageCheckSum:       {Name: params.ImageCheckSum, Type: params.Uint32, Value: uint32(2323432)},
			params.ImageBase:           {Name: params.ImageBase, Type: params.Address, Value: uint64(0x7ccb313833a3)},
			params.ImageSignatureType:  {Name: params.ImageSignatureType, Type: params.Enum, Value: uint32(0), Enum: signature.Types},
			params.ImageSignatureLevel: {Name: params.ImageSignatureLevel, Type: params.Enum, Value: uint32(0), Enum: signature.Levels},
			params.FileIsDotnet:        {Name: params.FileIsDotnet, Type: params.Bool, Value: false},
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
		matches := f.Run(e2)
		if matches != tt.matches {
			t.Errorf("%d. %q image filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}

	assert.NotNil(t, signature.GetSignatures().GetSignature(0x7ccb313833a3))

	e3 := &event.Event{
		Type:     event.LoadImage,
		Category: event.Image,
		Params: event.Params{
			params.ImagePath:           {Name: params.ImagePath, Type: params.UnicodeString, Value: "C:\\Windows\\System32\\mscorlib.dll"},
			params.ProcessID:           {Name: params.ProcessID, Type: params.PID, Value: uint32(1023)},
			params.ImageCheckSum:       {Name: params.ImageCheckSum, Type: params.Uint32, Value: uint32(2323432)},
			params.ImageBase:           {Name: params.ImageBase, Type: params.Address, Value: uint64(0xfff313833a3)},
			params.ImageSignatureType:  {Name: params.ImageSignatureType, Type: params.Enum, Value: uint32(0), Enum: signature.Types},
			params.ImageSignatureLevel: {Name: params.ImageSignatureLevel, Type: params.Enum, Value: uint32(0), Enum: signature.Levels},
			params.FileIsDotnet:        {Name: params.FileIsDotnet, Type: params.Bool, Value: true},
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
		matches := f.Run(e3)
		if matches != tt.matches {
			t.Errorf("%d. %q image filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}
}

func TestPEFilter(t *testing.T) {
	evt := &event.Event{
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
		matches := f.Run(evt)
		if matches != tt.matches {
			t.Errorf("%d. %q pe filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}
}

func TestLazyPEFilter(t *testing.T) {
	evt := &event.Event{
		Type: event.LoadImage,
		PS: &pstypes.PS{
			PID: 2312,
			Exe: filepath.Join(os.Getenv("windir"), "notepad.exe"),
		},
		Params: event.Params{
			params.FileIsDLL: {Name: params.FileIsDLL, Type: params.Bool, Value: true},
			params.FilePath:  {Name: params.FilePath, Type: params.UnicodeString, Value: "C:\\Windows\\system32\\user32.dll"},
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
		require.Nil(t, evt.PS.PE)
		matches := f.Run(evt)
		if matches != tt.matches {
			t.Errorf("%d. %q pe lazy filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
		require.NotNil(t, evt.PS.PE)
		evt.PS.PE = nil
	}
}

func TestMemFilter(t *testing.T) {
	pars := event.Params{
		params.MemRegionSize:  {Name: params.MemRegionSize, Type: params.Uint64, Value: uint64(8192)},
		params.MemBaseAddress: {Name: params.MemBaseAddress, Type: params.Address, Value: uint64(1311246336000)},
		params.MemAllocType:   {Name: params.MemAllocType, Type: params.Flags, Value: uint32(0x00001000 | 0x00002000), Flags: event.MemAllocationFlags},
		params.ProcessID:      {Name: params.ProcessID, Type: params.Uint32, Value: uint32(345)},
		params.MemProtect:     {Name: params.MemProtect, Type: params.Flags, Value: uint32(0x40), Flags: event.MemProtectionFlags},
		params.MemProtectMask: {Name: params.MemProtectMask, Type: params.AnsiString, Value: "RWX"},
		params.MemPageType:    {Name: params.MemPageType, Type: params.Enum, Value: uint32(0x1000000), Enum: processors.MemPageTypes},
	}

	evt := &event.Event{
		Type:     event.VirtualAlloc,
		Params:   pars,
		Name:     "VirtualAlloc",
		Category: event.Mem,
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
		matches := f.Run(evt)
		if matches != tt.matches {
			t.Errorf("%d. %q mem filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}
}

func TestDNSFilter(t *testing.T) {
	evt := &event.Event{
		Type: event.ReplyDNS,
		Tid:  2484,
		PID:  859,
		PS: &pstypes.PS{
			Name: "cmd.exe",
		},
		Category: event.Net,
		Params: event.Params{
			params.DNSName:    {Name: params.DNSName, Type: params.UnicodeString, Value: "r3.o.lencr.org"},
			params.DNSRR:      {Name: params.DNSRR, Type: params.Enum, Value: uint32(0x0001), Enum: event.DNSRecordTypes},
			params.DNSOpts:    {Name: params.DNSOpts, Type: params.Flags64, Value: uint64(0x00006000), Flags: event.DNSOptsFlags},
			params.DNSRcode:   {Name: params.DNSRcode, Type: params.Enum, Value: uint32(0), Enum: event.DNSResponseCodes},
			params.DNSAnswers: {Name: params.DNSAnswers, Type: params.Slice, Value: []string{"incoming.telemetry.mozilla.org", "a1887.dscq.akamai.net"}},
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
		matches := f.Run(evt)
		if matches != tt.matches {
			t.Errorf("%d. %q dns filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}
}

func TestThreadpoolFilter(t *testing.T) {
	e := &event.Event{
		Type:      event.SubmitThreadpoolCallback,
		Tid:       2484,
		PID:       1023,
		CPU:       1,
		Seq:       2,
		Name:      "SubmitThreadpoolCallback",
		Timestamp: time.Now(),
		Category:  event.Threadpool,
		Params: event.Params{
			params.ThreadpoolPoolID:           {Name: params.ThreadpoolPoolID, Type: params.Address, Value: uint64(0x20f5fc02440)},
			params.ThreadpoolTaskID:           {Name: params.ThreadpoolTaskID, Type: params.Address, Value: uint64(0x20f7ecd21f8)},
			params.ThreadpoolCallback:         {Name: params.ThreadpoolCallback, Type: params.Address, Value: uint64(0x7ffb3138592e)},
			params.ThreadpoolContext:          {Name: params.ThreadpoolContext, Type: params.Address, Value: uint64(0x14d0d16fed8)},
			params.ThreadpoolContextRip:       {Name: params.ThreadpoolContextRip, Type: params.Address, Value: uint64(0x143c9b07bd0)},
			params.ThreadpoolSubprocessTag:    {Name: params.ThreadpoolSubprocessTag, Type: params.Address, Value: uint64(0x10d)},
			params.ThreadpoolContextRipSymbol: {Name: params.ThreadpoolContextRipSymbol, Type: params.UnicodeString, Value: "VirtualProtect"},
			params.ThreadpoolContextRipModule: {Name: params.ThreadpoolContextRipModule, Type: params.UnicodeString, Value: "C:\\Windows\\System32\\kernelbase.dll"},
			params.ThreadpoolCallbackSymbol:   {Name: params.ThreadpoolCallbackSymbol, Type: params.UnicodeString, Value: "RtlDestroyQueryDebugBuffer"},
			params.ThreadpoolCallbackModule:   {Name: params.ThreadpoolCallbackModule, Type: params.UnicodeString, Value: "C:\\Windows\\System32\\ntdll.dll"},
			params.ThreadpoolTimerSubqueue:    {Name: params.ThreadpoolTimerSubqueue, Type: params.Address, Value: uint64(0x1db401703e8)},
			params.ThreadpoolTimerDuetime:     {Name: params.ThreadpoolTimerDuetime, Type: params.Uint64, Value: uint64(18446744073699551616)},
			params.ThreadpoolTimer:            {Name: params.ThreadpoolTimer, Type: params.Address, Value: uint64(0x3e8)},
			params.ThreadpoolTimerPeriod:      {Name: params.ThreadpoolTimerPeriod, Type: params.Uint32, Value: uint32(100)},
			params.ThreadpoolTimerWindow:      {Name: params.ThreadpoolTimerWindow, Type: params.Uint32, Value: uint32(50)},
			params.ThreadpoolTimerAbsolute:    {Name: params.ThreadpoolTimerAbsolute, Type: params.Bool, Value: true},
		},
	}

	var tests = []struct {
		filter  string
		matches bool
	}{

		{`threadpool.id = '20f5fc02440'`, true},
		{`threadpool.task.id = '20f7ecd21f8'`, true},
		{`threadpool.callback.address = '7ffb3138592e'`, true},
		{`threadpool.callback.symbol = 'RtlDestroyQueryDebugBuffer'`, true},
		{`threadpool.callback.module = 'C:\\Windows\\System32\\ntdll.dll'`, true},
		{`threadpool.callback.context = '14d0d16fed8'`, true},
		{`threadpool.callback.context.rip = '143c9b07bd0'`, true},
		{`threadpool.callback.context.rip.symbol = 'VirtualProtect'`, true},
		{`threadpool.callback.context.rip.module = 'C:\\Windows\\System32\\kernelbase.dll'`, true},
		{`threadpool.timer.address = '3e8'`, true},
		{`threadpool.timer.subqueue = '1db401703e8'`, true},
		{`threadpool.timer.duetime = 18446744073699551616`, true},
		{`threadpool.timer.period = 100`, true},
		{`threadpool.timer.window = 50`, true},
		{`threadpool.timer.is_absolute = true`, true},
	}

	for i, tt := range tests {
		f := New(tt.filter, cfg)
		err := f.Compile()
		if err != nil {
			t.Fatal(err)
		}
		matches := f.Run(e)
		if matches != tt.matches {
			t.Errorf("%d. %q threadpool filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}
}

func TestInterpolateFields(t *testing.T) {
	var tests = []struct {
		original     string
		interpolated string
		evts         []*event.Event
	}{
		{
			original:     "Credential discovery via %ps.name (%evt.arg[cmdline]) and user %ps.sid",
			interpolated: "Credential discovery via VaultCmd.exe (VaultCmd.exe /listcreds:Windows Credentials /all) and user LOCAL\\tor",
			evts: []*event.Event{
				{
					Type:     event.CreateProcess,
					Category: event.Process,
					Name:     "CreateProcess",
					PID:      1023,
					PS: &pstypes.PS{
						Name: "VaultCmd.exe",
						Ppid: 345,
						SID:  "LOCAL\\tor",
					},
					Params: event.Params{
						params.Cmdline: {Name: params.Cmdline, Type: params.UnicodeString, Value: `VaultCmd.exe /listcreds:Windows Credentials /all`},
					},
				},
			},
		},
		{
			original:     "Credential discovery via %ps.name and pid %evt.pid",
			interpolated: "Credential discovery via N/A and pid 1023",
			evts: []*event.Event{
				{
					Type:     event.CreateProcess,
					Category: event.Process,
					Name:     "CreateProcess",
					PID:      1023,
				},
			},
		},
		{
			original:     "Suspicious thread start module %thread.start_address.module",
			interpolated: "Suspicious thread start module C:\\Windows\\System32\\vault.dll",
			evts: []*event.Event{
				{
					Type:     event.CreateThread,
					Category: event.Thread,
					Name:     "CreateThread",
					PID:      1023,
					Params: event.Params{
						params.StartAddressModule: {Name: params.StartAddressModule, Type: params.UnicodeString, Value: "C:\\Windows\\System32\\vault.dll"},
					},
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
			evts: []*event.Event{
				{
					Type:     event.OpenProcess,
					Category: event.Process,
					Name:     "OpenProcess",
					PID:      1023,
					PS: &pstypes.PS{
						Name: "taskmgr.exe",
						Ppid: 345,
						SID:  "LOCAL\\tor",
					},
				},
				{
					Type:     event.WriteFile,
					Category: event.File,
					Name:     "WriteFile",
					PID:      1023,
					Params: event.Params{
						params.FilePath: {Name: params.FilePath, Type: params.UnicodeString, Value: "C:\\Users\neo\\Temp\\lsass.dump"},
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
			evts: []*event.Event{
				{
					Type:     event.OpenProcess,
					Category: event.Process,
					Name:     "OpenProcess",
					PID:      1023,
					PS: &pstypes.PS{
						Name: "taskmgr.exe",
						Ppid: 345,
						SID:  "LOCAL\\tor",
					},
				},
				{
					Type:     event.WriteFile,
					Category: event.File,
					Name:     "WriteFile",
					PID:      1023,
					Params: event.Params{
						params.FilePath: {Name: params.FilePath, Type: params.UnicodeString, Value: "C:\\Users\neo\\Temp\\lsass.dump"},
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

	pars := event.Params{
		params.Cmdline:         {Name: params.Cmdline, Type: params.UnicodeString, Value: "C:\\Windows\\system32\\svchost.exe -k RPCSS"},
		params.ProcessName:     {Name: params.ProcessName, Type: params.AnsiString, Value: "svchost.exe"},
		params.ProcessID:       {Name: params.ProcessID, Type: params.Uint32, Value: uint32(1234)},
		params.ProcessParentID: {Name: params.ProcessParentID, Type: params.Uint32, Value: uint32(345)},
	}

	evt := &event.Event{
		Type:   event.CreateProcess,
		Params: pars,
		Name:   "CreateProcess",
	}

	for i := 0; i < b.N; i++ {
		f.Run(evt)
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

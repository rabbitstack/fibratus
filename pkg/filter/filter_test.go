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
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/rabbitstack/fibratus/pkg/kstream/processors"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/pe"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/stretchr/testify/require"
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

func TestNarrowAccessors(t *testing.T) {
	var tests = []struct {
		f                Filter
		expectedAccesors int
	}{
		{
			New(`ps.name = 'cmd.exe' and kevt.name = 'CreateProcess' or kevt.name in ('TerminateProcess', 'CreateFile')`, cfg),
			2,
		},
		{
			New(`ps.modules[kernel32.dll].location = 'C:\\Windows\\System32'`, cfg),
			1,
		},
		{
			New(`handle.type = 'Section' and pe.sections > 1 and kevt.name = 'CreateHandle'`, cfg),
			3,
		},
		{
			New(`sequence |kevt.name = 'CreateProcess'| as e1 |kevt.name = 'CreateFile' and file.name = $e1.ps.exe |`, cfg),
			3,
		},
		{
			New(`base(file.name) = 'kernel32.dll'`, cfg),
			1,
		},
	}

	for i, tt := range tests {
		require.NoError(t, tt.f.Compile())
		naccessors := len(tt.f.(*filter).accessors)
		if tt.expectedAccesors != naccessors {
			t.Errorf("%d. accessors mismatch: exp=%d got=%d", i, tt.expectedAccesors, naccessors)
		}
	}
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
			SID:  "NT AUTHORITY\\SYSTEM",
			PID:  2034,
			Parent: &pstypes.PS{
				Name: "System",
			},
		},
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
			Envs:     map[string]string{"ALLUSERSPROFILE": "C:\\ProgramData", "OS": "Windows_NT", "ProgramFiles(x86)": "C:\\Program Files (x86)"},
			Modules: []pstypes.Module{
				{Name: "C:\\Windows\\System32\\kernel32.dll", Size: 12354, Checksum: 23123343, BaseAddress: kparams.Hex("fff23fff"), DefaultBaseAddress: kparams.Hex("fff124fd")},
				{Name: "C:\\Windows\\System32\\user32.dll", Size: 212354, Checksum: 33123343, BaseAddress: kparams.Hex("fef23fff"), DefaultBaseAddress: kparams.Hex("fff124fd")},
			},
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
				{Name: "C:\\Windows\\System32\\kernel32.dll", Size: 12354, Checksum: 23123343, BaseAddress: kparams.Hex("fff23fff"), DefaultBaseAddress: kparams.Hex("fff124fd")},
				{Name: "C:\\Windows\\System32\\user32.dll", Size: 212354, Checksum: 33123343, BaseAddress: kparams.Hex("fef23fff"), DefaultBaseAddress: kparams.Hex("fff124fd")},
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
		{`ps.envs in ('ALLUSERSPROFILE')`, true},
		{`kevt.name='CreateProcess' and ps.name contains 'svchost'`, true},

		{`ps.modules IN ('kernel32.dll')`, true},
		{`ps.modules[kernel32.dll].size = 12354`, true},
		{`ps.modules[kernel32.dll].checksum = 23123343`, true},
		{`ps.modules[kernel32.dll].address.default = 'fff124fd'`, true},
		{`ps.modules[kernel32.dll].address.base = 'fff23fff'`, true},
		{`ps.modules[kernel32.dll].location = 'C:\\Windows\\System32'`, true},
		{`ps.modules[xul.dll].size = 12354`, false},
		{`kevt.name = 'CreateProcess' and kevt.pid != ps.ppid`, true},
		{`ps.parent.name = 'wininit.exe'`, true},
		{`ps.ancestor[1].name = 'wininit.exe'`, true},
		{`ps.ancestor[2].name = 'services.exe'`, true},
		{`ps.ancestor[2].sid = 'NT AUTHORITY\\SYSTEM'`, true},
		{`ps.ancestor[root].name = 'System'`, true},
		{`ps.ancestor[any].name in ('services.exe', 'System')`, true},
		{`ps.ancestor[any].name not in ('svchost.exe')`, true},
		{`ps.ancestor[any].name endswith ('ices.exe')`, true},
		{`ps.ancestor[any].name iendswith ('TeM')`, true},
		{`ps.ancestor[any].name startswith ('serv')`, true},
		{`ps.ancestor[any].name istartswith ('Serv')`, true},
		{`ps.ancestor[any].name contains ('Sys')`, true},
		{`ps.ancestor[any].name icontains ('sys')`, true},
		{`ps.ancestor[any].pid in (2034, 343)`, true},
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
		kparams.Cmdline:         {Name: kparams.Cmdline, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\svchost.exe -k RPCSS"},
		kparams.ProcessName:     {Name: kparams.ProcessName, Type: kparams.AnsiString, Value: "svchost.exe"},
		kparams.ProcessID:       {Name: kparams.ProcessID, Type: kparams.Uint32, Value: uint32(1234)},
		kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.Uint32, Value: uint32(345)},
	}

	kevt := &kevent.Kevent{
		Type:     ktypes.CreateThread,
		Kparams:  kpars,
		Name:     "CreateThread",
		Category: ktypes.Thread,
		PS: &pstypes.PS{
			Name: "svchost.exe",
			Envs: map[string]string{"ALLUSERSPROFILE": "C:\\ProgramData", "OS": "Windows_NT", "ProgramFiles(x86)": "C:\\Program Files (x86)"},
		},
	}

	var tests = []struct {
		filter  string
		matches bool
	}{

		{`ps.name = 'svchost.exe'`, true},
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
			kparams.FileName:      {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\user32.dll"},
			kparams.FileType:      {Name: kparams.FileType, Type: kparams.AnsiString, Value: "file"},
			kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.AnsiString, Value: "open"},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	var tests = []struct {
		filter  string
		matches bool
	}{

		{`file.name = 'C:\\Windows\\system32\\user32.dll'`, true},
		{`file.extension  = '.dll'`, true},
		{`file.extension not contains '.exe'`, true},
		{`file.extension contains '.exe' or (file.extension contains '.dll' and file.name endswith 'user32.dll')`, true},
		{`file.extension = '.dll' or (file.extension contains '.exe' and file.name endswith 'kernel32.dll')`, true},
		{`file.extension not contains '.exe' and file.extension contains '.dll'`, true},
		{`file.extension not contains '.exe' and file.extension not contains '.com'`, true},
		{`file.extension not contains '.exe' and file.extension not contains '.com' and file.extension not in ('.vba', '.exe')`, true},
		{`file.extension not in ('.exe', '.com')`, true},
		{`file.extension not in ('.exe', '.dll')`, false},
		{`file.name matches 'C:\\*\\user32.dll'`, true},
		{`file.name not matches 'C:\\*.exe'`, true},
		{`file.name imatches 'C:\\*\\USER32.dll'`, true},
		{`file.name matches ('C:\\*\\user3?.dll', 'C:\\*\\user32.*')`, true},
		{`file.name contains ('C:\\Windows\\system32\\kernel32.dll', 'C:\\Windows\\system32\\user32.dll')`, true},
		{`file.name not matches ('C:\\*.exe', 'C:\\Windows\\*.com')`, true},
		{`file.name endswith ('.exe', 'kernel32.dll', 'user32.dll')`, true},
		{`file.name iendswith ('.EXE', 'KERNEL32.dll', 'user32.dll')`, true},
		{`file.name istartswith ('C:\\WINDOWS', 'KERNEL32.dll', 'user32.dll')`, true},
		{`file.name iin ('C:\\WINDOWS\\system32\\user32.dll')`, true},
		{`file.name fuzzy 'C:\\Windows\\system32\\ser3ll'`, true},
		{`file.name ifuzzy 'C:\\WINDOWS\\sYS\\ser3ll'`, true},
		{`file.name ifuzzy 'C:\\WINDOWS\\sYS\\32dll'`, true},
		{`file.name fuzzy ('C:\\Windows\\system32\\kernel', 'C:\\Windows\\system32\\ser3ll')`, true},
		{`file.name ifuzzynorm 'C:\\WINDOWS\\sÝS\\32dll'`, true},
		{`base(file.name) = 'user32.dll'`, true},
		{`ext(base(file.name)) = '.dll'`, true},
		{`base(file.name, false) = 'user32'`, true},
		{`dir(file.name) = 'C:\\Windows\\system32'`, true},
		{`ext(file.name) = '.dll'`, true},
		{`ext(file.name, false) = 'dll'`, true},
		{`is_abs(file.name)`, true},
		{`is_abs(base(file.name))`, false},
		{`file.name iin glob('C:\\Windows\\System32\\*.dll')`, true},
		{`volume(file.name) = 'C:'`, true},
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
			kparams.FileName:      {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll"},
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
		{`kevt.arg[file_name] = '\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll'`, true},
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
		{`split(file.name, '\\') IN ('windows', 'system32')`, true},
		{`length(file.name) = 51`, true},
		{`indexof(file.name, '\\') = 0`, true},
		{`indexof(file.name, '\\', 'last') = 40`, true},
		{`indexof(file.name, 'h2', 'any') = 22`, true},
		{`substr(file.name, indexof(file.name, '\\'), indexof(file.name, '\\Hard')) = '\\Device'`, true},
		{`substr(kevt.desc, indexof(kevt.desc, '\\'), indexof(kevt.desc, 'NOT')) = 'Creates or opens a new file, directory, I/O device, pipe, console'`, true},
		{`entropy(file.name) > 120`, true},
		{`regex(file.name, '\\\\Device\\\\HarddiskVolume[2-9]+\\\\.*')`, true},
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
			kparams.NetDport:    {Name: kparams.NetDport, Type: kparams.Uint16, Value: uint16(443)},
			kparams.NetSport:    {Name: kparams.NetSport, Type: kparams.Uint16, Value: uint16(43123)},
			kparams.NetSIP:      {Name: kparams.NetSIP, Type: kparams.IPv4, Value: net.ParseIP("127.0.0.1")},
			kparams.NetDIP:      {Name: kparams.NetDIP, Type: kparams.IPv4, Value: net.ParseIP("216.58.201.174")},
			kparams.NetDIPNames: {Name: kparams.NetDIPNames, Type: kparams.Slice, Value: []string{"dns.google.", "github.com."}},
			kparams.NetSIPNames: {Name: kparams.NetSIPNames, Type: kparams.Slice, Value: []string{"local.domain."}},
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
		{`net.dip.names in ('dns.google.')`, true},
		{`net.sip.names matches ('*.domain.')`, true},
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
}

func TestRegistryFilter(t *testing.T) {
	kevt := &kevent.Kevent{
		Type:     ktypes.RegSetValue,
		Tid:      2484,
		PID:      859,
		Category: ktypes.Registry,
		Kparams: kevent.Kparams{
			kparams.RegKeyName:   {Name: kparams.RegKeyName, Type: kparams.UnicodeString, Value: `HKEY_LOCAL_MACHINE\SYSTEM\Setup\Pid`},
			kparams.RegValue:     {Name: kparams.RegValue, Type: kparams.Uint32, Value: uint32(10234)},
			kparams.RegValueType: {Name: kparams.RegValueType, Type: kparams.AnsiString, Value: "DWORD"},
			kparams.NTStatus:     {Name: kparams.NTStatus, Type: kparams.AnsiString, Value: "success"},
			kparams.RegKeyHandle: {Name: kparams.RegKeyHandle, Type: kparams.HexInt64, Value: kparams.NewHex(uint64(18446666033449935464))},
		},
	}

	var tests = []struct {
		filter  string
		matches bool
	}{

		{`registry.status startswith ('key not', 'succ')`, true},
		{`registry.key.name icontains ('hkey_local_machine', 'HKEY_LOCAL')`, true},
		{`registry.value = 10234`, true},
		{`registry.value.type in ('DWORD', 'QWORD')`, true},
		{`MD5(registry.key.name) = 'eab870b2a516206575d2ffa2b98d8af5'`, true},
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

		{`pe.sections[.text].entropy = 6.368381`, true},
		{`pe.sections[.text].entropy > 4.45`, true},
		{`pe.sections[.text].size = 132608`, true},
		{`pe.symbols IN ('GetTextFaceW', 'GetProcessHeap')`, true},
		{`pe.resources[FileDesc] = 'Notepad'`, true},
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
and subsequently write the <code>%2.file.name</code> dump file to the disk device`,
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
						kparams.FileName: {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "C:\\Users\neo\\Temp\\lsass.dump"},
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
and subsequently write the <code>%2.file.name</code> dump file to the disk device`,
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
						kparams.FileName: {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "C:\\Users\neo\\Temp\\lsass.dump"},
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

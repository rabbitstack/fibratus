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
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/pe"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/stretchr/testify/require"
	"net"
	"testing"
	"time"
)

var cfg = &config.Config{
	Kstream: config.KstreamConfig{
		EnableHandleKevents:   true,
		EnableNetKevents:      true,
		EnableRegistryKevents: true,
		EnableFileIOKevents:   true,
		EnableImageKevents:    true,
		EnableThreadKevents:   true,
	},
	PE: pe.Config{Enabled: true},
}

func TestFilterCompile(t *testing.T) {
	f := New(`ps.name = 'cmd.exe'`, cfg)
	require.NoError(t, f.Compile())
	f = New(`'cmd.exe'`, cfg)
	require.EqualError(t, f.Compile(), "expected at least one field or operator but zero found")
	f = New(`ps.name`, cfg)
	require.EqualError(t, f.Compile(), "expected at least one field or operator but zero found")
	f = New(`ps.name =`, cfg)
	require.EqualError(t, f.Compile(), "ps.name =\n          ^ expected field, string, number, bool, ip")
}

func TestFilterRunProcessKevent(t *testing.T) {
	kpars := kevent.Kparams{
		kparams.Comm:            {Name: kparams.Comm, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\svchost.exe -k RPCSS"},
		kparams.ProcessName:     {Name: kparams.ProcessName, Type: kparams.AnsiString, Value: "svchost.exe"},
		kparams.ProcessID:       {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(1234)},
		kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.PID, Value: uint32(345)},
	}
	kevt := &kevent.Kevent{
		Type:    ktypes.CreateProcess,
		Kparams: kpars,
		Name:    "CreateProcess",
		PID:     1023,
		PS: &pstypes.PS{
			Ppid: 345,
			Envs: map[string]string{"ALLUSERSPROFILE": "C:\\ProgramData", "OS": "Windows_NT", "ProgramFiles(x86)": "C:\\Program Files (x86)"},
			Modules: []pstypes.Module{
				{Name: "C:\\Windows\\System32\\kernel32.dll", Size: 12354, Checksum: 23123343, BaseAddress: kparams.Hex("fff23fff"), DefaultBaseAddress: kparams.Hex("fff124fd")},
				{Name: "C:\\Windows\\System32\\user32.dll", Size: 212354, Checksum: 33123343, BaseAddress: kparams.Hex("fef23fff"), DefaultBaseAddress: kparams.Hex("fff124fd")},
			},
		},
	}
	kevt.Timestamp, _ = time.Parse(time.RFC3339, "2011-05-03T15:04:05.323Z")

	var tests = []struct {
		filter  string
		matches bool
	}{

		{`ps.name = 'svchost.exe'`, true},
		{`ps.name = 'svchot.exe'`, false},
		{`ps.name = 'mimikatz.exe' or ps.name contains 'svc'`, true},
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
	}

	for i, tt := range tests {
		f := New(tt.filter, cfg)
		err := f.Compile()
		if err != nil {
			t.Fatal(err)
		}
		matches := f.Run(kevt)
		if matches != tt.matches {
			t.Errorf("%d. %q ps filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}
}

func TestFilterRunThreadKevent(t *testing.T) {
	kpars := kevent.Kparams{
		kparams.Comm:            {Name: kparams.Comm, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\svchost.exe -k RPCSS"},
		kparams.ProcessName:     {Name: kparams.ProcessName, Type: kparams.AnsiString, Value: "svchost.exe"},
		kparams.ProcessID:       {Name: kparams.ProcessID, Type: kparams.Uint32, Value: uint32(1234)},
		kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.Uint32, Value: uint32(345)},
	}

	kevt := &kevent.Kevent{
		Type:    ktypes.CreateThread,
		Kparams: kpars,
		Name:    "CreateThread",
		PS: &pstypes.PS{
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

func TestFilterRunFileKevent(t *testing.T) {
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
		Metadata: map[string]string{"foo": "bar", "fooz": "barzz"},
	}

	var tests = []struct {
		filter  string
		matches bool
	}{

		{`file.name = 'C:\\Windows\\system32\\user32.dll'`, true},
		{`file.extension  = '.dll'`, true},
		{`file.extension not contains '.exe'`, true},
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

func TestFilterRunKevent(t *testing.T) {
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
			kparams.FileName:      {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll"},
			kparams.FileType:      {Name: kparams.FileType, Type: kparams.AnsiString, Value: "file"},
			kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.AnsiString, Value: "open"},
		},
		Metadata: map[string]string{"foo": "bar", "fooz": "barz"},
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
		{`kevt.nparams = 4`, true},

		{`kevt.desc contains 'Creates or opens a new file'`, true},

		{`kevt.date.d = 3 AND kevt.date.m = 5 AND kevt.time.s = 5 AND kevt.time.m = 4 and kevt.time.h = 15`, true},
		{`kevt.time = '15:04:05'`, true},
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

func TestFilterRunNetKevent(t *testing.T) {
	kevt := &kevent.Kevent{
		Type: ktypes.SendTCPv4,
		Tid:  2484,
		PID:  859,
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
		{`net.dip not in ('116.58.201.172', '16.58.201.176')`, true},
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

func TestFilterRunRegistryKevent(t *testing.T) {
	kevt := &kevent.Kevent{
		Type: ktypes.RegSetValue,
		Tid:  2484,
		PID:  859,
		Kparams: kevent.Kparams{
			kparams.RegKeyName:   {Name: kparams.RegKeyName, Type: kparams.UnicodeString, Value: `HKEY_LOCAL_MACHINE\SYSTEM\Setup\Pid`},
			kparams.RegValue:     {Name: kparams.RegValue, Type: kparams.Uint32, Value: 10234},
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

func TestFilterRunPE(t *testing.T) {
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
			t.Errorf("%d. %q ps filter mismatch: exp=%t got=%t", i, tt.filter, tt.matches, matches)
		}
	}

}

func BenchmarkFilterRun(b *testing.B) {
	b.ReportAllocs()
	f := New(`ps.name = 'mimikatz.exe' or ps.name contains 'svc'`, cfg)
	require.NoError(b, f.Compile())

	kpars := kevent.Kparams{
		kparams.Comm:            {Name: kparams.Comm, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\svchost.exe -k RPCSS"},
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

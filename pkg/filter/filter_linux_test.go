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
	"net"
	"testing"

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/stretchr/testify/require"
)

var cfg = &config.Config{
	EventSource: config.EventSourceConfig{
		EnableFileIOEvents: true,
		EnableNetEvents:    true,
		EnableMemEvents:    true,
	},
	Filters: &config.Filters{},
}

func evalFilter(t *testing.T, expr string, evt *event.Event) bool {
	t.Helper()
	f := New(expr, cfg)
	require.NoError(t, f.Compile(), expr)
	return f.Eval(evt)
}

func testPS() *pstypes.PS {
	parent := &pstypes.PS{
		PID:           1,
		Name:          "systemd",
		Cmdline:       "/sbin/init",
		Exe:           "/sbin/init",
		Cwd:           "/",
		Args:          []string{"/sbin/init"},
		Username:      "root",
		UID:           0,
		GID:           0,
		StartBootTime: 100,
		Envs:          map[string]string{"PATH": "/usr/sbin"},
	}
	return &pstypes.PS{
		PID:           4242,
		Ppid:          1,
		Name:          "bash",
		Cmdline:       "/bin/bash -lc test",
		Exe:           "/bin/bash",
		Cwd:           "/home/user",
		Args:          []string{"-lc", "test"},
		Username:      "user",
		UID:           1000,
		GID:           1000,
		StartBootTime: 200,
		Envs:          map[string]string{"HOME": "/home/user", "PATH": "/usr/bin"},
		Parent:        parent,
	}
}

func TestFilterCompile(t *testing.T) {
	f := New(`ps.name = 'bash'`, cfg)
	require.NoError(t, f.Compile())
	f = New(`'bash'`, cfg)
	require.EqualError(t, f.Compile(), "expected at least one field or operator but zero found")
	f = New(`ps.name`, cfg)
	require.EqualError(t, f.Compile(), "expected at least one field or operator but zero found")
	f = New(`file.path = '/tmp/x'`, cfg)
	require.NoError(t, f.Compile())
	f = New(`net.dport = 443`, cfg)
	require.NoError(t, f.Compile())
	f = New(`mem.size > 4096`, cfg)
	require.NoError(t, f.Compile())
	f = New(`ps.name =`, cfg)
	require.Error(t, f.Compile())
}

func TestWindowsOnlyFieldsUnavailable(t *testing.T) {
	exprs := []string{
		`kevt.pid = 1`,
		`kevt.name = 'execve'`,
		`kevt.arg[exe] = '/bin/bash'`,
		`ps.sid = 'S-1-5-18'`,
		`registry.path = 'HKLM'`,
		`pe.address.entrypoint = '20110'`,
		`file.object = 1`,
		`mem.type = 'PRIVATE'`,
		`mem.alloc = 'COMMIT'`,
		`handle.name = 'mutant'`,
		`dns.name = 'example.org'`,
		`evt.is_direct_syscall = true`,
	}
	for _, expr := range exprs {
		f := New(expr, cfg)
		require.Error(t, f.Compile(), expr)
	}
}

func TestSharedFieldSemantics(t *testing.T) {
	ps := testPS()
	openat := &event.Event{
		Type:     event.Openat,
		Category: event.File,
		Name:     "openat",
		PID:      4242,
		Tid:      4242,
		PS:       ps,
		Params: event.Params{
			params.FilePath: {Name: params.FilePath, Type: params.Path, Value: "/tmp/secret.txt"},
		},
	}
	connect := &event.Event{
		Type:     event.Connect,
		Category: event.Net,
		Name:     "connect",
		PID:      4242,
		PS:       ps,
		Params: event.Params{
			params.NetDIP:   {Name: params.NetDIP, Type: params.IPv4, Value: net.IPv4(1, 2, 3, 4).To4()},
			params.NetDport: {Name: params.NetDport, Type: params.Port, Value: uint16(443)},
		},
	}
	mmap := &event.Event{
		Type:     event.Mmap,
		Category: event.Mem,
		Name:     "mmap",
		PID:      4242,
		PS:       ps,
		Params: event.Params{
			params.MemBaseAddress: {Name: params.MemBaseAddress, Type: params.Address, Value: uint64(8192)},
			params.MemRegionSize:  {Name: params.MemRegionSize, Type: params.Uint64, Value: uint64(4096)},
			params.MemProtect:     {Name: params.MemProtect, Type: params.Uint32, Value: uint32(3)},
		},
	}

	require.True(t, evalFilter(t, `ps.name = 'bash'`, openat))
	require.True(t, evalFilter(t, `ps.exe = '/bin/bash'`, openat))
	require.True(t, evalFilter(t, `ps.cmdline contains 'bash'`, openat))
	require.True(t, evalFilter(t, `ps.uuid > 0`, openat))
	require.True(t, evalFilter(t, `file.path = '/tmp/secret.txt'`, openat))
	require.True(t, evalFilter(t, `file.name = 'secret.txt'`, openat))
	require.True(t, evalFilter(t, `file.extension = '.txt'`, openat))
	require.True(t, evalFilter(t, `file.path.stem = '/tmp/secret'`, openat))
	require.True(t, evalFilter(t, `net.dip = 1.2.3.4`, connect))
	require.True(t, evalFilter(t, `net.dport = 443`, connect))
	require.True(t, evalFilter(t, `mem.address = 8192`, mmap))
	require.True(t, evalFilter(t, `mem.size = 4096`, mmap))
	require.True(t, evalFilter(t, `mem.protection = 3`, mmap))
}

func TestProcFilter(t *testing.T) {
	ps := testPS()
	execve := &event.Event{
		Type:     event.Execve,
		Category: event.Process,
		Name:     "execve",
		PID:      4242,
		Tid:      4242,
		CPU:      2,
		PS:       ps,
		Params: event.Params{
			params.Retval:    {Name: params.Retval, Type: params.Int64, Value: int64(0)},
			params.SyscallID: {Name: params.SyscallID, Type: params.Uint32, Value: uint32(59)},
			params.UID:       {Name: params.UID, Type: params.Uint32, Value: uint32(1000)},
			params.GID:       {Name: params.GID, Type: params.Uint32, Value: uint32(1000)},
			params.Exe:       {Name: params.Exe, Type: params.Path, Value: "/bin/bash"},
		},
	}
	kill := &event.Event{
		Type:     event.Kill,
		Category: event.Process,
		Name:     "kill",
		PID:      4242,
		PS:       ps,
		Params: event.Params{
			params.TargetProcessID: {Name: params.TargetProcessID, Type: params.PID, Value: uint64(99)},
			params.Signal:          {Name: params.Signal, Type: params.Int32, Value: int32(9)},
			params.Retval:          {Name: params.Retval, Type: params.Int64, Value: int64(0)},
		},
	}
	ptrace := &event.Event{
		Type:     event.Ptrace,
		Category: event.Process,
		Name:     "ptrace",
		PID:      4242,
		PS:       ps,
		Params: event.Params{
			params.PtraceRequest:   {Name: params.PtraceRequest, Type: params.Int64, Value: int64(16)},
			params.TargetProcessID: {Name: params.TargetProcessID, Type: params.PID, Value: uint64(99)},
		},
	}
	prctl := &event.Event{
		Type:     event.Prctl,
		Category: event.Process,
		Name:     "prctl",
		PID:      4242,
		PS:       ps,
		Params: event.Params{
			params.PrctlOption: {Name: params.PrctlOption, Type: params.Int64, Value: int64(15)},
		},
	}
	clone := &event.Event{
		Type:     event.Clone,
		Category: event.Process,
		Name:     "clone",
		PID:      4242,
		PS:       ps,
		Params: event.Params{
			params.CloneFlags: {Name: params.CloneFlags, Type: params.Uint64, Value: uint64(0)},
		},
	}

	tests := []struct {
		evt    *event.Event
		filter string
		want   bool
	}{
		{execve, `ps.name = 'bash'`, true},
		{execve, `ps.name = 'zsh'`, false},
		{execve, `ps.pid = 4242`, true},
		{execve, `ps.ppid = 1`, true},
		{execve, `ps.parent.pid = 1`, true},
		{execve, `ps.parent.name = 'systemd'`, true},
		{execve, `ps.parent.args in ('/sbin/init')`, true},
		{execve, `ps.parent.cwd = '/'`, true},
		{execve, `ps.parent.username = 'root'`, true},
		{execve, `ps.uid = 1000`, true},
		{execve, `ps.gid = 1000`, true},
		{execve, `ps.username = 'user'`, true},
		{execve, `ps.args in ('-lc', 'test')`, true},
		{execve, `ps.envs[HOME] = '/home/user'`, true},
		{execve, `ps.envs[HO] = '/home/user'`, true},
		{execve, `ps.uuid > 0`, true},
		{execve, `ps.parent.uuid > 0`, true},
		{execve, `evt.name = 'execve'`, true},
		{execve, `evt.pid = 4242`, true},
		{execve, `evt.tid = 4242`, true},
		{execve, `evt.cpu = 2`, true},
		{execve, `evt.retval = 0`, true},
		{execve, `evt.syscall = 59`, true},
		{execve, `evt.arg[exe] = '/bin/bash'`, true},
		{kill, `ps.signal = 9`, true},
		{kill, `ps.target.pid = 99`, true},
		{ptrace, `ps.ptrace.request = 16`, true},
		{ptrace, `ps.target.pid = 99`, true},
		{prctl, `ps.prctl.option = 15`, true},
		{clone, `ps.clone.flags = 0`, true},
	}
	for i, tt := range tests {
		got := evalFilter(t, tt.filter, tt.evt)
		if got != tt.want {
			t.Errorf("%d. %q mismatch: exp=%t got=%t", i, tt.filter, tt.want, got)
		}
	}
}

func TestFileFilter(t *testing.T) {
	openat := &event.Event{
		Type:     event.Openat,
		Category: event.File,
		Name:     "openat",
		PID:      4242,
		Params: event.Params{
			params.FilePath:  {Name: params.FilePath, Type: params.Path, Value: "/etc/passwd"},
			params.DirFD:     {Name: params.DirFD, Type: params.Int64, Value: int64(-100)},
			params.FileFlags: {Name: params.FileFlags, Type: params.Uint64, Value: uint64(0)},
			params.FileMode:  {Name: params.FileMode, Type: params.Uint64, Value: uint64(420)},
			params.FD:        {Name: params.FD, Type: params.Int64, Value: int64(3)},
			params.Retval:    {Name: params.Retval, Type: params.Int64, Value: int64(3)},
		},
	}
	rename := &event.Event{
		Type:     event.Rename,
		Category: event.File,
		Name:     "rename",
		PID:      4242,
		Params: event.Params{
			params.FilePath:    {Name: params.FilePath, Type: params.Path, Value: "/tmp/old"},
			params.FileNewPath: {Name: params.FileNewPath, Type: params.Path, Value: "/tmp/new"},
		},
	}
	unlink := &event.Event{
		Type:     event.Unlink,
		Category: event.File,
		Name:     "unlink",
		PID:      4242,
		Params: event.Params{
			params.FilePath: {Name: params.FilePath, Type: params.Path, Value: "/tmp/gone.log"},
		},
	}

	tests := []struct {
		evt    *event.Event
		filter string
		want   bool
	}{
		{openat, `file.path = '/etc/passwd'`, true},
		{openat, `file.name = 'passwd'`, true},
		{openat, `file.dirfd < 0`, true},
		{openat, `file.fd = 3`, true},
		{openat, `file.flags = 0`, true},
		{openat, `file.mode = 420`, true},
		{openat, `evt.retval = 3`, true},
		{rename, `file.new_path = '/tmp/new'`, true},
		{rename, `file.path = '/tmp/old'`, true},
		{unlink, `file.extension = '.log'`, true},
		{unlink, `file.name = 'gone.log'`, true},
	}
	for i, tt := range tests {
		got := evalFilter(t, tt.filter, tt.evt)
		if got != tt.want {
			t.Errorf("%d. %q mismatch: exp=%t got=%t", i, tt.filter, tt.want, got)
		}
	}
}

func TestNetFilter(t *testing.T) {
	connect := &event.Event{
		Type:     event.Connect,
		Category: event.Net,
		Name:     "connect",
		PID:      4242,
		Params: event.Params{
			params.FD:         {Name: params.FD, Type: params.Int64, Value: int64(5)},
			params.SockFamily: {Name: params.SockFamily, Type: params.Uint16, Value: uint16(2)},
			params.NetDIP:     {Name: params.NetDIP, Type: params.IPv4, Value: net.IPv4(172, 17, 0, 3).To4()},
			params.NetDport:   {Name: params.NetDport, Type: params.Port, Value: uint16(443)},
		},
	}
	accept := &event.Event{
		Type:     event.Accept,
		Category: event.Net,
		Name:     "accept",
		PID:      4242,
		Params: event.Params{
			params.FD:         {Name: params.FD, Type: params.Int64, Value: int64(6)},
			params.SockFamily: {Name: params.SockFamily, Type: params.Uint16, Value: uint16(2)},
			params.NetSIP:     {Name: params.NetSIP, Type: params.IPv4, Value: net.IPv4(127, 0, 0, 1).To4()},
			params.NetSport:   {Name: params.NetSport, Type: params.Port, Value: uint16(80)},
		},
	}
	unixc := &event.Event{
		Type:     event.Connect,
		Category: event.Net,
		Name:     "connect",
		PID:      4242,
		Params: event.Params{
			params.FD:         {Name: params.FD, Type: params.Int64, Value: int64(7)},
			params.SockFamily: {Name: params.SockFamily, Type: params.Uint16, Value: uint16(1)},
			params.SockPath:   {Name: params.SockPath, Type: params.Path, Value: "/tmp/app.sock"},
		},
	}

	require.True(t, evalFilter(t, `net.dip = 172.17.0.3`, connect))
	require.True(t, evalFilter(t, `net.dport = 443`, connect))
	require.True(t, evalFilter(t, `net.family = 2`, connect))
	require.True(t, evalFilter(t, `net.fd = 5`, connect))
	require.True(t, evalFilter(t, `net.sip = 127.0.0.1`, accept))
	require.True(t, evalFilter(t, `net.sport = 80`, accept))
	require.True(t, evalFilter(t, `net.path = '/tmp/app.sock'`, unixc))
	require.True(t, evalFilter(t, `net.family = 1`, unixc))
}

func TestMemFilter(t *testing.T) {
	mmap := &event.Event{
		Type:     event.Mmap,
		Category: event.Mem,
		Name:     "mmap",
		PID:      4242,
		Params: event.Params{
			params.MemBaseAddress: {Name: params.MemBaseAddress, Type: params.Address, Value: uint64(8192)},
			params.MemRegionSize:  {Name: params.MemRegionSize, Type: params.Uint64, Value: uint64(8192)},
			params.MemProtect:     {Name: params.MemProtect, Type: params.Uint32, Value: uint32(3)},
			params.MmapFlags:      {Name: params.MmapFlags, Type: params.Uint64, Value: uint64(1)},
			params.FD:             {Name: params.FD, Type: params.Int64, Value: int64(3)},
			params.MmapOffset:     {Name: params.MmapOffset, Type: params.Uint64, Value: uint64(0)},
		},
	}
	vmread := &event.Event{
		Type:     event.ProcessVMRead,
		Category: event.Mem,
		Name:     "process_vm_readv",
		PID:      4242,
		Params: event.Params{
			params.TargetProcessID: {Name: params.TargetProcessID, Type: params.PID, Value: uint64(99)},
			params.MemBaseAddress:  {Name: params.MemBaseAddress, Type: params.Address, Value: uint64(4096)},
			params.MemRegionSize:   {Name: params.MemRegionSize, Type: params.Uint64, Value: uint64(16)},
		},
	}
	vmwrite := &event.Event{
		Type:     event.ProcessVMWrite,
		Category: event.Mem,
		Name:     "process_vm_writev",
		PID:      4242,
		Params: event.Params{
			params.TargetProcessID: {Name: params.TargetProcessID, Type: params.PID, Value: uint64(77)},
			params.MemBaseAddress:  {Name: params.MemBaseAddress, Type: params.Address, Value: uint64(4096)},
		},
	}

	require.True(t, evalFilter(t, `mem.address = 8192`, mmap))
	require.True(t, evalFilter(t, `mem.size = 8192`, mmap))
	require.True(t, evalFilter(t, `mem.protection = 3`, mmap))
	require.True(t, evalFilter(t, `mem.flags = 1`, mmap))
	require.True(t, evalFilter(t, `mem.fd = 3`, mmap))
	require.True(t, evalFilter(t, `mem.offset = 0`, mmap))
	require.True(t, evalFilter(t, `mem.target.pid = 99`, vmread))
	require.True(t, evalFilter(t, `mem.target.pid = 77`, vmwrite))
}

func TestThreadFilter(t *testing.T) {
	cloneThread := &event.Event{
		Type:     event.Clone,
		Category: event.Process,
		Name:     "clone",
		PID:      4242,
		Tid:      4243,
		Params: event.Params{
			params.CloneFlags: {Name: params.CloneFlags, Type: params.Uint64, Value: uint64(0x00010000)},
		},
	}
	cloneProc := &event.Event{
		Type:     event.Clone,
		Category: event.Process,
		Name:     "clone",
		PID:      4242,
		Tid:      4242,
		Params: event.Params{
			params.CloneFlags: {Name: params.CloneFlags, Type: params.Uint64, Value: uint64(0)},
		},
	}

	require.True(t, evalFilter(t, `thread.tid = 4243`, cloneThread))
	require.True(t, evalFilter(t, `thread.pid = 4242`, cloneThread))
	require.False(t, evalFilter(t, `thread.tid = 4243`, cloneProc))
}

func TestDefaultAndMissingValues(t *testing.T) {
	empty := &event.Event{
		Type:     event.Execve,
		Category: event.Process,
		Name:     "execve",
		PID:      7,
		Params:   event.Params{},
	}
	fileEvt := &event.Event{
		Type:     event.Openat,
		Category: event.File,
		Name:     "openat",
		PID:      7,
		Params:   event.Params{},
	}

	require.True(t, evalFilter(t, `evt.retval = 0`, empty))
	require.True(t, evalFilter(t, `evt.truncated = false`, empty))
	require.True(t, evalFilter(t, `ps.signal = 0`, empty))
	require.True(t, evalFilter(t, `file.path = ''`, fileEvt))
	require.True(t, evalFilter(t, `not (file.path = '/tmp/x')`, fileEvt))
	require.True(t, evalFilter(t, `file.fd = 0`, fileEvt))
	require.True(t, evalFilter(t, `file.truncated = false`, fileEvt))
	require.True(t, evalFilter(t, `mem.size = 0`, &event.Event{Type: event.Mmap, Category: event.Mem, Name: "mmap", Params: event.Params{}}))
}

func TestTruncatedFields(t *testing.T) {
	filenameTrunc := &event.Event{
		Type:     event.Openat,
		Category: event.File,
		Name:     "openat",
		Params: event.Params{
			params.FilePath:  {Name: params.FilePath, Type: params.Path, Value: "/tmp/partial"},
			params.Truncated: {Name: params.Truncated, Type: params.Uint32, Value: uint32(1)},
		},
	}
	auxTrunc := &event.Event{
		Type:     event.Rename,
		Category: event.File,
		Name:     "rename",
		Params: event.Params{
			params.FilePath:    {Name: params.FilePath, Type: params.Path, Value: "/tmp/old"},
			params.FileNewPath: {Name: params.FileNewPath, Type: params.Path, Value: "/tmp/partial-dest"},
			params.Truncated:   {Name: params.Truncated, Type: params.Uint32, Value: uint32(2)},
		},
	}

	notTrunc := &event.Event{
		Type:     event.Openat,
		Category: event.File,
		Name:     "openat",
		Params: event.Params{
			params.FilePath: {Name: params.FilePath, Type: params.Path, Value: "/tmp/full"},
		},
	}

	require.True(t, evalFilter(t, `file.truncated = true`, filenameTrunc))
	require.True(t, evalFilter(t, `evt.truncated = true`, filenameTrunc))
	require.True(t, evalFilter(t, `file.truncated = true`, auxTrunc))
	require.True(t, evalFilter(t, `evt.truncated = true`, auxTrunc))
	require.True(t, evalFilter(t, `file.truncated = false`, notTrunc))
	require.True(t, evalFilter(t, `evt.truncated = false`, notTrunc))
}

func TestEveryLinuxEventType(t *testing.T) {
	ps := testPS()
	cases := []struct {
		evt    *event.Event
		filter string
	}{
		{&event.Event{Type: event.Execve, Category: event.Process, Name: "execve", PS: ps, Params: event.Params{params.Retval: {Name: params.Retval, Type: params.Int64, Value: int64(0)}}}, `evt.name = 'execve' and ps.name = 'bash'`},
		{&event.Event{Type: event.Exit, Category: event.Process, Name: "exit", PS: ps, Params: event.Params{params.Retval: {Name: params.Retval, Type: params.Int64, Value: int64(0)}}}, `evt.name = 'exit' and evt.retval = 0`},
		{&event.Event{Type: event.Clone, Category: event.Process, Name: "clone", PS: ps, Params: event.Params{params.CloneFlags: {Name: params.CloneFlags, Type: params.Uint64, Value: uint64(0)}}}, `evt.name = 'clone' and ps.clone.flags = 0`},
		{&event.Event{Type: event.Openat, Category: event.File, Name: "openat", PS: ps, Params: event.Params{params.FilePath: {Name: params.FilePath, Type: params.Path, Value: "/tmp/x"}}}, `file.path = '/tmp/x'`},
		{&event.Event{Type: event.Unlink, Category: event.File, Name: "unlink", PS: ps, Params: event.Params{params.FilePath: {Name: params.FilePath, Type: params.Path, Value: "/tmp/x"}}}, `file.name = 'x'`},
		{&event.Event{Type: event.Rename, Category: event.File, Name: "rename", PS: ps, Params: event.Params{params.FileNewPath: {Name: params.FileNewPath, Type: params.Path, Value: "/tmp/y"}}}, `file.new_path = '/tmp/y'`},
		{&event.Event{Type: event.Connect, Category: event.Net, Name: "connect", PS: ps, Params: event.Params{params.NetDport: {Name: params.NetDport, Type: params.Port, Value: uint16(443)}}}, `net.dport = 443`},
		{&event.Event{Type: event.Accept, Category: event.Net, Name: "accept", PS: ps, Params: event.Params{params.NetSport: {Name: params.NetSport, Type: params.Port, Value: uint16(80)}}}, `net.sport = 80`},
		{&event.Event{Type: event.Mmap, Category: event.Mem, Name: "mmap", PS: ps, Params: event.Params{params.MemRegionSize: {Name: params.MemRegionSize, Type: params.Uint64, Value: uint64(4096)}}}, `mem.size = 4096`},
		{&event.Event{Type: event.ProcessVMRead, Category: event.Mem, Name: "process_vm_readv", PS: ps, Params: event.Params{params.TargetProcessID: {Name: params.TargetProcessID, Type: params.PID, Value: uint64(9)}}}, `mem.target.pid = 9`},
		{&event.Event{Type: event.ProcessVMWrite, Category: event.Mem, Name: "process_vm_writev", PS: ps, Params: event.Params{params.TargetProcessID: {Name: params.TargetProcessID, Type: params.PID, Value: uint64(8)}}}, `mem.target.pid = 8`},
		{&event.Event{Type: event.Kill, Category: event.Process, Name: "kill", PS: ps, Params: event.Params{params.Signal: {Name: params.Signal, Type: params.Int32, Value: int32(9)}}}, `ps.signal = 9`},
		{&event.Event{Type: event.Ptrace, Category: event.Process, Name: "ptrace", PS: ps, Params: event.Params{params.PtraceRequest: {Name: params.PtraceRequest, Type: params.Int64, Value: int64(16)}}}, `ps.ptrace.request = 16`},
		{&event.Event{Type: event.Prctl, Category: event.Process, Name: "prctl", PS: ps, Params: event.Params{params.PrctlOption: {Name: params.PrctlOption, Type: params.Int64, Value: int64(15)}}}, `ps.prctl.option = 15`},
	}
	for _, tt := range cases {
		require.True(t, evalFilter(t, tt.filter, tt.evt), tt.filter)
	}
}

func TestIsFieldAccessible(t *testing.T) {
	fileEvt := &event.Event{Category: event.File}
	netEvt := &event.Event{Category: event.Net}
	memEvt := &event.Event{Category: event.Mem}
	procEvt := &event.Event{Category: event.Process, PS: testPS()}
	cloneThread := &event.Event{
		Type:     event.Clone,
		Category: event.Process,
		Params:   event.Params{params.CloneFlags: {Name: params.CloneFlags, Type: params.Uint64, Value: uint64(0x00010000)}},
	}

	require.True(t, newFileAccessor().IsFieldAccessible(fileEvt))
	require.False(t, newFileAccessor().IsFieldAccessible(procEvt))
	require.True(t, newNetworkAccessor().IsFieldAccessible(netEvt))
	require.True(t, newMemAccessor().IsFieldAccessible(memEvt))
	require.True(t, newPSAccessor(nil).IsFieldAccessible(procEvt))
	require.True(t, newThreadAccessor().IsFieldAccessible(cloneThread))
	require.False(t, newThreadAccessor().IsFieldAccessible(procEvt))
}

func TestGetAccessorsIncludesMatrix(t *testing.T) {
	accessors := GetAccessors()
	require.Len(t, accessors, 6)
}

func TestFieldCatalogTypes(t *testing.T) {
	require.Equal(t, params.Uint64, fields.PsUUID.Type())
	require.Equal(t, params.Uint32, fields.PsUID.Type())
	require.Equal(t, params.Int64, fields.PsSignal.Type())
	require.Equal(t, params.Bool, fields.FileTruncated.Type())
	require.Equal(t, params.Bool, fields.EvtTruncated.Type())
}

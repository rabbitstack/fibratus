//go:build linux

/*
 * Copyright 2026 by Mostafa Moradian
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

package ebpf

import (
	"testing"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/ps"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type matrixRow struct {
	name     string
	typ      event.Type
	syscalls []string
	hook     string
	params   []string
}

const hookSyscallIO = "tp/syscalls enter/exit"

func syscallMatrix() []matrixRow {
	return []matrixRow{
		{"execve", event.Execve, []string{"execve", "execveat"}, hookSyscallIO, []string{params.Exe, params.Retval}},
		{"exit", event.Exit, []string{"sched_process_exit"}, "tp_btf/sched_process_exit", []string{params.ExitStatus}},
		{"clone", event.Clone, []string{"clone", "clone3", "fork", "vfork"}, "tp/syscalls + tp_btf/sched_process_fork", []string{params.CloneFlags}},
		{"openat", event.Openat, []string{"open", "openat", "openat2"}, hookSyscallIO, []string{params.FilePath, params.DirFD, params.FileFlags, params.Retval}},
		{"unlink", event.Unlink, []string{"unlink", "unlinkat"}, hookSyscallIO, []string{params.FilePath, params.DirFD, params.Retval}},
		{"rename", event.Rename, []string{"rename", "renameat", "renameat2"}, hookSyscallIO, []string{params.FilePath, params.FileNewPath, params.Retval}},
		{"connect", event.Connect, []string{"connect"}, "tp/syscalls enter/exit; sockaddr copied at enter", []string{params.FD, params.SockFamily, params.Retval}},
		{"accept", event.Accept, []string{"accept", "accept4"}, "tp/syscalls enter/exit; sockaddr copied at exit", []string{params.FD, params.SockFamily, params.Retval}},
		{"mmap", event.Mmap, []string{"mmap"}, hookSyscallIO, []string{params.MemBaseAddress, params.MemRegionSize, params.MemProtect, params.MmapFlags, params.Retval}},
		{"process_vm_readv", event.ProcessVMRead, []string{"process_vm_readv"}, "tp/syscalls enter/exit; first remote iovec only", []string{params.TargetProcessID, params.MemBaseAddress, params.Retval}},
		{"process_vm_writev", event.ProcessVMWrite, []string{"process_vm_writev"}, "tp/syscalls enter/exit; first remote iovec only", []string{params.TargetProcessID, params.MemBaseAddress, params.Retval}},
		{"kill", event.Kill, []string{"kill", "tkill", "tgkill"}, "tp_btf/sys_exit", []string{params.TargetProcessID, params.Signal, params.Retval}},
		{"ptrace", event.Ptrace, []string{"ptrace"}, "tp_btf/sys_exit", []string{params.PtraceRequest, params.TargetProcessID, params.Retval}},
		{"prctl", event.Prctl, []string{"prctl"}, "tp_btf/sys_exit", []string{params.PrctlOption, params.Retval}},
	}
}

func TestSyscallEventMatrix(t *testing.T) {
	seen := map[event.Type]bool{}
	for _, row := range syscallMatrix() {
		assert.Equal(t, row.name, row.typ.String())
		assert.NotEmpty(t, row.syscalls)
		assert.NotEmpty(t, row.hook)
		seen[row.typ] = true
		raw := rawEvent{Type: uint32(row.typ), Retval: 0, Filename: [256]byte{'/'}, Aux: [256]byte{'/'}}
		if row.typ == event.Connect || row.typ == event.Accept {
			raw.Aux[0] = byte(unix.AF_INET)
			raw.Aux[1] = 0
			raw.Aux[2] = 0
			raw.Aux[3] = 80
			raw.Aux[4] = 127
			raw.Aux[5] = 0
			raw.Aux[6] = 0
			raw.Aux[7] = 1
		}
		evt := raw.toEvent()
		require.Equal(t, row.typ, evt.Type, row.name)
		for _, name := range row.params {
			_, err := evt.Params.Get(name)
			assert.NoErrorf(t, err, "%s missing param %s", row.name, name)
		}
	}
	for _, typ := range event.AllTypes() {
		assert.Truef(t, seen[typ], "event type %s missing from the syscall matrix", typ)
	}
}

func TestParseSockaddr(t *testing.T) {
	var inet [256]byte
	inet[0] = byte(unix.AF_INET)
	inet[2] = 0x00
	inet[3] = 0x50
	inet[4] = 10
	inet[5] = 1
	inet[6] = 2
	inet[7] = 3
	family, ip, port, unixPath := parseSockaddr(inet[:])
	assert.Equal(t, uint16(unix.AF_INET), family)
	assert.Equal(t, "10.1.2.3", ip.String())
	assert.Equal(t, uint16(80), port)
	assert.Empty(t, unixPath)

	var un [256]byte
	un[0] = byte(unix.AF_UNIX)
	copy(un[2:], "/tmp/fibratus.sock")
	family, ip, port, unixPath = parseSockaddr(un[:])
	assert.Equal(t, uint16(unix.AF_UNIX), family)
	assert.Nil(t, ip)
	assert.Equal(t, "/tmp/fibratus.sock", unixPath)
	assert.Zero(t, port)
}

func TestMmapUpdatesProcessState(t *testing.T) {
	snap := ps.NewSnapshotter()
	ps := &pstypes.PS{PID: 9, Name: "target", StartBootTime: 1, Threads: map[uint32]pstypes.Thread{}}
	snap.Put(ps)

	raw := rawEvent{Type: uint32(event.Mmap), PID: 9, TGID: 9, Retval: 0x1000, Arg0: 4096, Arg1: 8192, Arg2: 3, Arg3: 3, Flags: 0}
	evt := raw.toEvent()
	applyProcessState(snap, evt)
	ok, got := snap.Find(9)
	require.True(t, ok)
	require.Len(t, got.Mmaps, 1)
	assert.Equal(t, uint64(0x1000), uint64(got.Mmaps[0].BaseAddress))
	assert.Equal(t, uint64(8192), got.Mmaps[0].Size)
	assert.Equal(t, "file", got.Mmaps[0].Type)
}

func TestAnonymousMmapSkipped(t *testing.T) {
	snap := ps.NewSnapshotter()
	ps := &pstypes.PS{PID: 9, Name: "target", StartBootTime: 1, Threads: map[uint32]pstypes.Thread{}}
	snap.Put(ps)

	raw := rawEvent{Type: uint32(event.Mmap), PID: 9, TGID: 9, Retval: 0x1000, Arg1: 8192, Arg2: 3, Arg3: ^uint64(0), Flags: 0x20}
	evt := raw.toEvent()
	applyProcessState(snap, evt)
	ok, got := snap.Find(9)
	require.True(t, ok)
	assert.Empty(t, got.Mmaps)
}

func TestFailedSyscallKeepsProcessState(t *testing.T) {
	snap := ps.NewSnapshotter()
	snap.Put(&pstypes.PS{PID: 11, Name: "keep", StartBootTime: 4})
	raw := rawEvent{Type: uint32(event.Openat), PID: 11, TGID: 11, Retval: -2}
	copy(raw.Filename[:], "/no/such")
	evt := raw.toEvent()
	applyProcessState(snap, evt)
	ok, got := snap.Find(11)
	require.True(t, ok)
	assert.Equal(t, "keep", got.Name)
	assert.Empty(t, got.Mmaps)
}

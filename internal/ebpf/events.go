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
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/util/hostname"
)

const (
	// snapshotType marks iter/task baseline records. It maps to
	// event.UnknownType, so snapshots can never leak as live events.
	snapshotType = 0

	commLen     = 16
	filenameLen = 256
)

// rawEvent mirrors struct syscall_event in c/common/events.h.
type rawEvent struct {
	Type          uint32
	PID           uint32
	TID           uint32
	TGID          uint32
	PPID          uint32
	UID           uint32
	GID           uint32
	SyscallID     uint32
	Retval        int64
	Flags         uint64
	Arg0          uint64
	Arg1          uint64
	Arg2          uint64
	Arg3          uint64
	StartBootTime uint64
	TimestampNs   uint64
	Truncated     uint32
	Pad           uint32
	Comm          [commLen]byte
	Filename      [filenameLen]byte
	Aux           [filenameLen]byte
}

func decodeRawEvent(raw []byte) (rawEvent, error) {
	var ev rawEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
		return ev, fmt.Errorf("decoding eBPF event: %w", err)
	}
	return ev, nil
}

func (r rawEvent) comm() string     { return cString(r.Comm[:]) }
func (r rawEvent) filename() string { return cString(r.Filename[:]) }
func (r rawEvent) aux() string      { return cString(r.Aux[:]) }

func (r rawEvent) eventType() event.Type {
	return event.Type(r.Type)
}

func (r rawEvent) processID() uint32 {
	if r.PID != 0 {
		return r.PID
	}
	return r.TGID
}

// toEvent converts the raw eBPF record into an event. The sequence number is
// assigned at dispatch time, mirroring the Windows consumer which increments
// the sequencer only for events that pass exclusion and filtering.
func (r rawEvent) toEvent() *event.Event {
	typ := r.eventType()
	evt := &event.Event{
		PID:       r.processID(),
		Tid:       r.TID,
		Type:      typ,
		Host:      hostname.Get(),
		Timestamp: time.Unix(0, int64(r.TimestampNs)),
		Params:    event.NewParams(typ),
		Metadata:  make(event.Metadata),
	}
	evt.Params.SetByName(params.ProcessID, params.U32(evt.PID))
	evt.Params.SetByName(params.ThreadID, params.U32(evt.Tid))
	evt.Params.SetByName(params.ProcessParentID, params.U32(r.PPID))
	evt.Params.SetByName(params.ProcessName, params.Str(r.comm()))
	evt.Params.SetByName(params.UID, params.U32(r.UID))
	evt.Params.SetByName(params.GID, params.U32(r.GID))
	evt.Params.SetByName(params.SyscallID, params.U32(r.SyscallID))
	evt.Params.SetByName(params.Retval, params.I64(r.Retval))
	evt.Params.SetByName(params.StartBootTime, params.U64(r.StartBootTime))

	switch typ {
	case event.Execve:
		name := r.filename()
		if name == "" {
			name = r.comm()
		}
		evt.Params.SetByName(params.Exe, params.Str(name))
		evt.Params.SetByName(params.Cmdline, params.Str(name))
	case event.Exit:
		evt.Params.SetByName(params.ExitStatus, params.I64(r.Retval))
	case event.Clone:
		evt.Params.SetByName(params.CloneFlags, params.U64(r.Flags))
	case event.Openat:
		evt.Params.SetByName(params.DirFD, params.I64(int64(r.Arg0)))
		evt.Params.SetByName(params.FilePath, params.Str(r.filename()))
		evt.Params.SetByName(params.FileFlags, params.U64(r.Flags))
		evt.Params.SetByName(params.FileMode, params.U64(r.Arg1))
		if r.Retval >= 0 {
			evt.Params.SetByName(params.FD, params.I64(r.Retval))
		}
	case event.Unlink:
		evt.Params.SetByName(params.DirFD, params.I64(int64(r.Arg0)))
		evt.Params.SetByName(params.FilePath, params.Str(r.filename()))
		evt.Params.SetByName(params.FileFlags, params.U64(r.Flags))
	case event.Rename:
		evt.Params.SetByName(params.DirFD, params.I64(int64(r.Arg0)))
		evt.Params.SetByName(params.NewDirFD, params.I64(int64(r.Arg1)))
		evt.Params.SetByName(params.FilePath, params.Str(r.filename()))
		evt.Params.SetByName(params.FileNewPath, params.Str(r.aux()))
		evt.Params.SetByName(params.FileFlags, params.U64(r.Flags))
	case event.Connect, event.Accept:
		appendSockParams(evt, r)
	case event.Mmap:
		addr := uint64(0)
		if r.Retval >= 0 {
			addr = uint64(r.Retval)
		}
		evt.Params.SetByName(params.MemBaseAddress, params.U64(addr))
		evt.Params.SetByName(params.MemRegionSize, params.U64(r.Arg1))
		evt.Params.SetByName(params.MemProtect, params.U32(uint32(r.Arg2)))
		evt.Params.SetByName(params.MmapFlags, params.U64(r.Flags))
		evt.Params.SetByName(params.FD, params.I64(int64(r.Arg3)))
		evt.Params.SetByName(params.MmapOffset, params.U64(r.Arg0))
	case event.ProcessVMRead, event.ProcessVMWrite:
		evt.Params.SetByName(params.TargetProcessID, params.I64(int64(int32(r.Arg0))))
		evt.Params.SetByName(params.MemBaseAddress, params.U64(r.Arg2))
		evt.Params.SetByName(params.MemRegionSize, params.U64(r.Arg3))
		evt.Params.SetByName(params.MmapFlags, params.U64(r.Flags))
	case event.Kill:
		evt.Params.SetByName(params.TargetProcessID, params.I64(int64(int32(r.Arg0))))
		evt.Params.SetByName(params.Signal, params.I32(int32(r.Arg1)))
	case event.Ptrace:
		evt.Params.SetByName(params.PtraceRequest, params.I64(int64(r.Arg0)))
		evt.Params.SetByName(params.TargetProcessID, params.I64(int64(int32(r.Arg1))))
		evt.Params.SetByName(params.PtraceAddr, params.U64(r.Arg2))
		evt.Params.SetByName(params.PtraceData, params.U64(r.Arg3))
	case event.Prctl:
		evt.Params.SetByName(params.PrctlOption, params.I64(int64(r.Arg0)))
	}
	if r.Truncated != 0 {
		evt.Params.SetByName(params.Truncated, params.U32(r.Truncated))
	}
	return evt
}

func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

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
	Type      uint32
	PID       uint32
	TID       uint32
	TGID      uint32
	PPID      uint32
	UID       uint32
	GID       uint32
	SyscallID uint32
	Retval    int64
	// Flags is interpreted per event type; clone stores the raw clone flags.
	Flags         uint64
	StartBootTime uint64
	TimestampNs   uint64
	Comm          [commLen]byte
	Filename      [filenameLen]byte
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

func (r rawEvent) eventType() event.Type {
	switch r.Type {
	case uint32(event.Execve):
		return event.Execve
	case uint32(event.Exit):
		return event.Exit
	case uint32(event.Clone):
		return event.Clone
	default:
		return event.UnknownType
	}
}

func (r rawEvent) processID() uint64 {
	if r.PID != 0 {
		return uint64(r.PID)
	}
	return uint64(r.TGID)
}

// toEvent converts the raw eBPF record into an event. The sequence number is
// assigned at dispatch time, mirroring the Windows consumer which increments
// the sequencer only for events that pass exclusion and filtering.
func (r rawEvent) toEvent() *event.Event {
	typ := r.eventType()
	info := event.TypeToEventInfo(typ)
	evt := &event.Event{
		PID:         r.processID(),
		Tid:         uint64(r.TID),
		Type:        typ,
		Name:        info.Name,
		Category:    info.Category,
		Description: info.Description,
		Host:        hostname.Get(),
		Timestamp:   time.Unix(0, int64(r.TimestampNs)),
		Params:      event.Params{},
		Metadata:    make(event.Metadata),
	}
	evt.Params.Append(params.ProcessID, params.PID, evt.PID)
	evt.Params.Append(params.ThreadID, params.TID, evt.Tid)
	evt.Params.Append(params.ProcessParentID, params.PID, uint64(r.PPID))
	evt.Params.Append(params.ProcessName, params.String, r.comm())
	evt.Params.Append(params.UID, params.Uint32, r.UID)
	evt.Params.Append(params.GID, params.Uint32, r.GID)
	evt.Params.Append(params.SyscallID, params.Uint32, r.SyscallID)
	evt.Params.Append(params.Retval, params.Int64, r.Retval)
	evt.Params.Append(params.StartBootTime, params.Uint64, r.StartBootTime)

	switch typ {
	case event.Execve:
		name := r.filename()
		if name == "" {
			name = r.comm()
		}
		evt.Params.Append(params.Exe, params.Path, name)
		evt.Params.Append(params.Cmdline, params.String, name)
	case event.Exit:
		evt.Params.Append(params.ExitStatus, params.Int64, r.Retval)
	case event.Clone:
		evt.Params.Append(params.CloneFlags, params.Uint64, r.Flags)
	}
	return evt
}

func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

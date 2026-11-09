/*
 * Copyright 2026 by Nedim Sabic Sabic
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

package testutil

import (
	"time"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
)

// baseTime is the default timestamp of the events built by MakeEvent.
var baseTime = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

// BaseTime returns the default timestamp of the events built by MakeEvent.
func BaseTime() time.Time { return baseTime }

// EventOption customizes the event built by MakeEvent.
type EventOption func(*event.Event)

// MakeEvent builds the event of the given type. The event name, category
// and description are derived from the type metadata. By default, the event
// has no params, no process state and the timestamp is BaseTime.
func MakeEvent(t event.Type, opts ...EventOption) *event.Event {
	e := &event.Event{
		Type:      t,
		Timestamp: baseTime,
		Params:    make(event.Params),
		Metadata:  make(event.Metadata),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// WithPID sets the identifier of the process that generated the event.
func WithPID(pid uint32) EventOption { return func(e *event.Event) { e.PID = pid } }

// WithTID sets the identifier of the thread that generated the event.
func WithTID(tid uint32) EventOption { return func(e *event.Event) { e.Tid = tid } }

// WithSeq sets the event sequence number.
func WithSeq(seq uint64) EventOption { return func(e *event.Event) { e.Seq = seq } }

// WithTimestamp sets the event timestamp.
func WithTimestamp(ts time.Time) EventOption { return func(e *event.Event) { e.Timestamp = ts } }

// WithOffset sets the event timestamp relative to BaseTime.
func WithOffset(d time.Duration) EventOption {
	return func(e *event.Event) { e.Timestamp = baseTime.Add(d) }
}

// WithParam appends the event parameter.
func WithParam(name string, typ params.Type, value params.Value) EventOption {
	return func(e *event.Event) { e.Params.Append(name, typ, value) }
}

// WithMetadata attaches the metadata tag to the event.
func WithMetadata(key event.MetadataKey, value any) EventOption {
	return func(e *event.Event) { e.Metadata[key] = value }
}

// WithPS sets the process state of the event. If the event
// has no pid, it is taken from the process state.
func WithPS(ps *pstypes.PS) EventOption {
	return func(e *event.Event) {
		e.PS = ps
		if e.PID == 0 && ps != nil {
			e.PID = ps.PID
		}
	}
}

// PSOption customizes the process state built by MakePS.
type PSOption func(*pstypes.PS)

// MakePS builds the process state with the given pid and image name.
func MakePS(pid uint32, name string, opts ...PSOption) *pstypes.PS {
	ps := &pstypes.PS{
		PID:       pid,
		Name:      name,
		StartTime: baseTime,
		Threads:   make(map[uint32]pstypes.Thread),
		Modules:   make([]pstypes.Module, 0),
	}
	for _, opt := range opts {
		opt(ps)
	}
	return ps
}

// PSPpid sets the parent process identifier.
func PSPpid(ppid uint32) PSOption { return func(ps *pstypes.PS) { ps.Ppid = ppid } }

// PSExe sets the full path of the process executable.
func PSExe(exe string) PSOption { return func(ps *pstypes.PS) { ps.Exe = exe } }

// PSCmdline sets the process command line.
func PSCmdline(cmdline string) PSOption { return func(ps *pstypes.PS) { ps.Cmdline = cmdline } }

// PSSID sets the security identifier of the process.
func PSSID(sid string) PSOption { return func(ps *pstypes.PS) { ps.SID = sid } }

// PSParent sets the parent process state.
func PSParent(parent *pstypes.PS) PSOption {
	return func(ps *pstypes.PS) {
		ps.Parent = parent
		if ps.Ppid == 0 && parent != nil {
			ps.Ppid = parent.PID
		}
	}
}

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
	"expvar"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/ps"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
)

var (
	eventsProcessed = expvar.NewInt("ebpf.events.processed")
	eventsExcluded  = expvar.NewInt("ebpf.events.excluded")
	eventsUnknown   = expvar.NewInt("ebpf.events.unknown")
	parseErrors     = expvar.NewInt("ebpf.events.parse.errors")
	pendingQueued   = expvar.NewInt("ebpf.startup.pending.queued")
	pendingDropped  = expvar.NewInt("ebpf.startup.pending.dropped")
	replayApplied   = expvar.NewInt("ebpf.startup.replay.applied")
	snapshotUpserts = expvar.NewInt("ebpf.startup.snapshot.upserts")
	lateSnapshots   = expvar.NewInt("ebpf.startup.snapshot.late")
	enrichmentMiss  = expvar.NewInt("ebpf.enrichment.miss")
	ringbufDrops    = expvar.NewInt("ebpf.ringbuf.drops")
)

func applyProcessState(psnap ps.Snapshotter, evt *event.Event) {
	if evt == nil || psnap == nil {
		return
	}
	switch {
	case evt.Type == event.Execve && succeeded(evt):
		ps := buildPS(evt, psnap)
		evt.PS = ps
		_ = psnap.Write(evt)
	case evt.Type == event.Clone && succeeded(evt) && evt.IsCreateProcess():
		ps := buildPS(evt, psnap)
		evt.PS = ps
		psnap.Put(ps)
	case evt.Type == event.Clone && succeeded(evt) && evt.IsCreateThread():
		ok, existing := psnap.Find(evt.PID)
		if ok && existing != nil {
			evt.PS = existing
			_ = psnap.AddThread(evt)
		}
	case evt.Type == event.Exit:
		ok, existing := psnap.Find(evt.PID)
		if ok {
			evt.PS = existing
		}
		_ = psnap.Remove(evt)
	default:
		ok, existing := psnap.Find(evt.PID)
		if ok {
			evt.PS = existing
		}
	}
	if evt.PS == nil {
		ok, existing := psnap.Find(evt.PID)
		if ok {
			evt.PS = existing
		}
	}
}

func upsertSnapshot(psnap ps.Snapshotter, rec *pstypes.PS) {
	if psnap == nil || rec == nil {
		return
	}
	ok, existing := psnap.Find(rec.PID)
	if !ok || existing == nil {
		psnap.Put(rec)
		snapshotUpserts.Add(1)
		return
	}
	if existing.StartBootTime != rec.StartBootTime {
		psnap.Put(rec)
		snapshotUpserts.Add(1)
		return
	}
	mergePS(existing, rec)
	snapshotUpserts.Add(1)
}

func mergePS(dst, src *pstypes.PS) {
	if src.Name != "" {
		dst.Name = src.Name
	}
	if src.Exe != "" {
		dst.Exe = src.Exe
	}
	if src.Cmdline != "" {
		dst.Cmdline = src.Cmdline
	}
	if src.Ppid != 0 {
		dst.Ppid = src.Ppid
	}
	if src.UID != 0 {
		dst.UID = src.UID
	}
	if src.GID != 0 {
		dst.GID = src.GID
	}
	if src.StartBootTime != 0 {
		dst.StartBootTime = src.StartBootTime
	}
}

func buildPS(evt *event.Event, psnap ps.Snapshotter) *pstypes.PS {
	ok, existing := psnap.Find(evt.PID)
	exe := evt.GetParamAsString(params.Exe)
	cmdline := evt.GetParamAsString(params.Cmdline)
	name := evt.GetParamAsString(params.ProcessName)
	if exe == "" && existing != nil {
		exe = existing.Exe
	}
	if cmdline == "" && existing != nil {
		cmdline = existing.Cmdline
	}
	if name == "" {
		name = baseName(exe)
	}
	ps := &pstypes.PS{
		PID:           evt.PID,
		Ppid:          evt.GetParamAsUint64(params.ProcessParentID),
		Name:          name,
		Cmdline:       cmdline,
		Exe:           exe,
		Args:          splitCmdline(cmdline),
		StartBootTime: evt.GetParamAsUint64(params.StartBootTime),
		UID:           evt.GetParamAsUint32(params.UID),
		GID:           evt.GetParamAsUint32(params.GID),
		Threads:       make(map[uint64]pstypes.Thread),
	}
	if ok && existing != nil && existing.StartBootTime == ps.StartBootTime && existing.Threads != nil {
		ps.Threads = existing.Threads
		ps.Parent = existing.Parent
	}
	if ok, parent := psnap.Find(ps.Ppid); ok {
		ps.Parent = parent
	}
	return ps
}

func succeeded(evt *event.Event) bool {
	ret, err := evt.Params.GetInt64(params.Retval)
	if err != nil {
		return true
	}
	return ret >= 0
}

func enrichEvent(evt *event.Event) {
	if evt == nil {
		return
	}
	exe, cmdline, err := enrichFromProc(evt.PID)
	if err != nil {
		enrichmentMiss.Add(1)
	}
	if exe != "" {
		evt.Params.Append(params.Exe, params.Path, exe)
		if evt.GetParamAsString(params.ProcessName) == "" {
			evt.Params.Append(params.ProcessName, params.String, baseName(exe))
		}
	}
	if cmdline != "" {
		evt.Params.Append(params.Cmdline, params.String, cmdline)
	}
}

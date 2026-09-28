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
)

func TestApplyProcessStateExecveAndPIDReuse(t *testing.T) {
	snap := ps.NewSnapshotter()
	first := sampleExecve().toEvent()
	applyProcessState(snap, first)
	ok, got := snap.Find(4242)
	require.True(t, ok)
	assert.Equal(t, "/bin/bash", got.Exe)
	assert.Equal(t, uint64(123456789), got.StartBootTime)
	assert.Equal(t, got.UUID(), first.PS.UUID())

	reuse := sampleExecve().toEvent()
	reuse.Params.Append(params.StartBootTime, params.Uint64, uint64(999))
	reuse.Params.Append(params.Exe, params.Path, "/bin/sh")
	reuse.Params.Append(params.ProcessName, params.String, "sh")
	applyProcessState(snap, reuse)
	ok, got = snap.Find(4242)
	require.True(t, ok)
	assert.Equal(t, "/bin/sh", got.Exe)
	assert.Equal(t, uint64(999), got.StartBootTime)
	assert.NotEqual(t, first.PS.UUID(), got.UUID())
}

func TestApplyProcessStateExitRemoves(t *testing.T) {
	snap := ps.NewSnapshotter()
	evt := sampleExecve().toEvent()
	applyProcessState(snap, evt)
	exit := &event.Event{
		Type:   event.Exit,
		PID:    4242,
		Params: event.Params{},
	}
	exit.Params.Append(params.Retval, params.Int64, int64(0))
	applyProcessState(snap, exit)
	ok, _ := snap.Find(4242)
	assert.False(t, ok)
}

func TestUpsertSnapshotIgnoresAfterLiveReplacement(t *testing.T) {
	snap := ps.NewSnapshotter()
	rec := &pstypes.PS{PID: 7, Name: "snap", StartBootTime: 9, Exe: "/bin/snap"}
	upsertSnapshot(snap, rec)
	ok, got := snap.Find(7)
	require.True(t, ok)
	assert.Equal(t, "snap", got.Name)

	live := &event.Event{Type: event.Execve, PID: 7, Params: event.Params{}}
	live.Params.Append(params.ProcessName, params.String, "live")
	live.Params.Append(params.Exe, params.Path, "/bin/live")
	live.Params.Append(params.StartBootTime, params.Uint64, uint64(9))
	live.Params.Append(params.Retval, params.Int64, int64(0))
	applyProcessState(snap, live)

	upsertSnapshot(snap, &pstypes.PS{PID: 7, Name: "stale", StartBootTime: 9, Exe: "/bin/stale"})
	ok, got = snap.Find(7)
	require.True(t, ok)
	assert.Equal(t, "stale", got.Name)
}

func TestPendingBackpressure(t *testing.T) {
	es := &EventSource{pendingCap: 2}
	require.True(t, es.enqueuePending(&event.Event{PID: 1}))
	require.True(t, es.enqueuePending(&event.Event{PID: 2}))
	require.False(t, es.enqueuePending(&event.Event{PID: 3}))
	assert.Len(t, es.pending, 2)
}

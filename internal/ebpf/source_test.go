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

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testConfig() *config.Config {
	cfg := &config.Config{ForwardMode: true}
	cfg.EventSource.EnableFileIOEvents = true
	cfg.EventSource.EnableNetEvents = true
	cfg.EventSource.EnableMemEvents = true
	cfg.EventSource.Init()
	return cfg
}

func TestStartupReplayAndLateSnapshot(t *testing.T) {
	cfg := testConfig()
	es := NewEventSource(ps.NewSnapshotter(), cfg, nil).(*EventSource)

	hot := sampleExecve()
	hot.PID = 42
	hot.TGID = 42
	hot.StartBootTime = 100
	hot.Comm = [16]byte{}
	hot.Filename = [256]byte{}
	copy(hot.Comm[:], "hot-a")
	copy(hot.Filename[:], "/bin/hot-a")
	es.handleRecord(encodeRaw(t, hot))
	require.Len(t, es.pending, 1)
	ok, _ := es.psnap.Find(42)
	assert.False(t, ok)

	snap := hot
	snap.Type = snapshotType
	snap.Comm = [16]byte{}
	copy(snap.Comm[:], "snap-a")
	es.handleSnapshot(snap)
	ok, got := es.psnap.Find(42)
	require.True(t, ok)
	assert.Equal(t, "snap-a", got.Name)

	es.finishBaseline()
	assert.True(t, es.live.Load())
	assert.Nil(t, es.pending)

	select {
	case evt := <-es.Events():
		assert.Equal(t, event.Execve, evt.Type)
		assert.Equal(t, uint64(42), evt.PID)
		require.NotNil(t, evt.PS)
		assert.Equal(t, "hot-a", evt.PS.Name)
		assert.Equal(t, uint64(100), evt.PS.StartBootTime)
	default:
		t.Fatal("expected replayed execve on the output queue")
	}

	late := snap
	late.Comm = [16]byte{}
	copy(late.Comm[:], "stale")
	es.handleSnapshot(late)
	ok, got = es.psnap.Find(42)
	require.True(t, ok)
	assert.Equal(t, "hot-a", got.Name)
}

func TestPIDReuseKeepsDistinctUUIDs(t *testing.T) {
	cfg := testConfig()
	es := NewEventSource(ps.NewSnapshotter(), cfg, nil).(*EventSource)
	es.live.Store(true)

	first := sampleExecve()
	first.PID = 8
	first.TGID = 8
	first.StartBootTime = 1
	first.Comm = [16]byte{}
	copy(first.Comm[:], "one")
	es.handleRecord(encodeRaw(t, first))

	exit := rawEvent{Type: uint32(event.Exit), PID: 8, TGID: 8, StartBootTime: 1}
	es.handleRecord(encodeRaw(t, exit))

	second := first
	second.StartBootTime = 2
	second.Comm = [16]byte{}
	second.Filename = [256]byte{}
	copy(second.Comm[:], "two")
	copy(second.Filename[:], "/bin/two")
	es.handleRecord(encodeRaw(t, second))

	ok, got := es.psnap.Find(8)
	require.True(t, ok)
	assert.Equal(t, "two", got.Name)
	assert.Equal(t, uint64(2), got.StartBootTime)
}

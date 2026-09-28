//go:build linux && ebpf_integration

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
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/api"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/util/rest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStatsSurfaceOverLiveCapture drives the same path fibratus stats takes:
// the API over its default UNIX socket, reading expvars produced by a live
// capture. Unit tests can assert the counters exist, but only this shows the
// command surface reporting numbers a running sensor actually moved.
func TestStatsSurfaceOverLiveCapture(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "fibratus.sock")
	cfg := testConfig()
	cfg.API.Transport = "unix://" + socket
	cfg.API.Timeout = 5 * time.Second

	es := NewEventSource(ps.NewSnapshotter(), cfg, nil, nil).(*EventSource)
	require.NoError(t, es.Open(cfg))
	t.Cleanup(func() { _ = es.Close() })

	require.NoError(t, api.StartServer(cfg))
	t.Cleanup(func() { require.NoError(t, api.CloseServer()) })

	// Drain, otherwise the queue fills and the counters stop advancing.
	go func() {
		for range es.Events() {
		}
	}()

	var vars map[string]any
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		_ = exec.Command("/bin/sh", "-c", "true").Run()

		body, err := rest.Get(rest.WithTransport(cfg.API.Transport), rest.WithURI("debug/vars"))
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &vars))
		if processed, ok := vars["ebpf.events.processed"].(float64); ok && processed > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	require.Contains(t, vars, "ebpf.events.processed")
	assert.Greater(t, vars["ebpf.events.processed"], float64(0), "no events were captured")

	// Every counter the Linux stats table renders has to be present, or the
	// command prints a zero for something that is simply not published.
	for _, name := range []string{
		"ebpf.events.excluded",
		"ebpf.events.unknown",
		"ebpf.events.parse.errors",
		"ebpf.ringbuf.drops",
		"ebpf.approver.drops",
		"ebpf.enrichment.miss",
		"ebpf.startup.pending.queued",
		"ebpf.startup.pending.dropped",
		"ebpf.startup.replay.applied",
		"ebpf.startup.snapshot.upserts",
		"ebpf.startup.snapshot.late",
	} {
		assert.Contains(t, vars, name)
	}
}

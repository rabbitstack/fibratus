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
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/stretchr/testify/require"
)

func TestLiveProcessSource(t *testing.T) {
	cfg := testConfig()
	es := NewEventSource(ps.NewSnapshotter(), cfg, nil, nil).(*EventSource)
	if err := es.Open(cfg); err != nil {
		t.Fatalf("opening process source: %v", err)
	}
	t.Cleanup(func() { _ = es.Close() })

	cmd := execLookPath()
	p, err := os.StartProcess(cmd, []string{cmd}, &os.ProcAttr{
		Files: []*os.File{nil, nil, nil},
	})
	require.NoError(t, err)
	_, _ = p.Wait()

	deadline := time.Now().Add(5 * time.Second)
	var sawExec, sawExit bool
	for time.Now().Before(deadline) && (!sawExec || !sawExit) {
		select {
		case evt := <-es.Events():
			switch evt.Type {
			case event.Execve:
				if evt.PID == uint64(p.Pid) {
					sawExec = true
				}
			case event.Exit:
				if evt.PID == uint64(p.Pid) {
					sawExit = true
				}
			}
		case err := <-es.Errors():
			t.Fatalf("event source error: %v", err)
		case <-time.After(50 * time.Millisecond):
		}
	}
	if !sawExec {
		t.Fatal("did not observe execve for spawned process")
	}
	if !sawExit {
		t.Fatal("did not observe exit for spawned process")
	}
}

func execLookPath() string {
	for _, p := range []string{"/bin/true", "/usr/bin/true"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "/bin/sh"
}

func TestLiveSyscallTelemetry(t *testing.T) {
	cfg := testConfig()
	es := NewEventSource(ps.NewSnapshotter(), cfg, nil, nil).(*EventSource)
	if err := es.Open(cfg); err != nil {
		t.Fatalf("opening process source: %v", err)
	}
	t.Cleanup(func() { _ = es.Close() })

	dir := t.TempDir()
	path := filepath.Join(dir, "x")
	script := "echo hi > \"$1\" && mv \"$1\" \"$1.new\" && rm -f \"$1.new\" && kill -0 $$"
	cmd := exec.Command("/bin/sh", "-c", script, "sh", path)
	require.NoError(t, cmd.Run())

	deadline := time.Now().Add(5 * time.Second)
	saw := map[event.Type]bool{}
	for time.Now().Before(deadline) && (!saw[event.Openat] || !saw[event.Rename] || !saw[event.Unlink] || !saw[event.Kill]) {
		select {
		case evt := <-es.Events():
			switch evt.Type {
			case event.Openat, event.Rename, event.Unlink, event.Kill, event.Mmap:
				saw[evt.Type] = true
			}
		case err := <-es.Errors():
			t.Fatalf("event source error: %v", err)
		case <-time.After(50 * time.Millisecond):
		}
	}
	if !saw[event.Openat] {
		t.Fatal("did not observe openat")
	}
	if !saw[event.Rename] {
		t.Fatal("did not observe rename")
	}
	if !saw[event.Unlink] {
		t.Fatal("did not observe unlink")
	}
	if !saw[event.Kill] {
		t.Fatal("did not observe kill")
	}
}

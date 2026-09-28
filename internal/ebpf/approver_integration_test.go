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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/stretchr/testify/require"
)

// TestApproverDecisionsMatchLoadedPrograms exercises the compiled BPF logic
// rather than the Go model in ApproverPlan.Allows. The two are separate
// implementations of the same predicate, so the soundness property is only
// worth as much as this test.
func TestApproverDecisionsMatchLoadedPrograms(t *testing.T) {
	dir := t.TempDir()
	allowed := filepath.Join(dir, "allowed.txt")
	require.NoError(t, os.WriteFile(allowed, []byte("x"), 0o600))

	// Establish first that the capture path reports this exact open with no
	// approver installed. If that fails, the problem is the enter/exit
	// correlation rather than the prefilter, and the second phase would
	// otherwise blame the approver for it.
	baseline := watchOpens(t, nil, allowed)
	require.True(t, baseline.sawAllowed,
		"capture never reported the open with no approver installed; pid=%d selfOpens=%d saw %q",
		os.Getpid(), baseline.selfOpens, baseline.seen)

	// Written as a matches pattern rather than startswith so the rewrite into
	// the LPM trie is covered too.
	plan := filter.PlanFromFilter(mustCompile(t,
		"evt.name = 'openat' and file.path matches '"+dir+"/*'"))
	got := watchOpens(t, plan, allowed)

	require.True(t, got.sawAllowed,
		"openat matching the approved pattern never reached userspace; wanted %q, selfOpens=%d saw %q, rejects %d -> %d",
		allowed, got.selfOpens, got.seen, got.rejectsBefore, got.rejectsAfter)
	require.False(t, got.sawDenied, "openat outside the approved pattern reached userspace")
	require.Greater(t, got.rejectsAfter, got.rejectsBefore, "approver reject counter did not advance")
}

type openWatch struct {
	sawAllowed    bool
	sawDenied     bool
	seen          []string
	selfOpens     int
	rejectsBefore uint64
	rejectsAfter  uint64
}

const deniedPath = "/etc/hostname"

// watchOpens repeatedly opens allowed and a denied path while draining events,
// returning what reached userspace. Correlating sys_enter_openat with its exit
// goes through a bounded LRU map, so on a loaded machine any single open can
// lose its scratch entry and arrive with no path at all. Retrying keeps the
// assertions about the approver rather than about that.
func watchOpens(t *testing.T, plan *filter.ApproverPlan, allowed string) openWatch {
	t.Helper()
	cfg := testConfig()
	es := NewEventSource(ps.NewSnapshotter(), cfg, nil, plan).(*EventSource)
	require.NoError(t, es.Open(cfg))
	defer func() { _ = es.Close() }()

	w := openWatch{seen: make([]string, 0, 16), rejectsBefore: es.loader.approverRejects()}

	attempts := time.NewTicker(200 * time.Millisecond)
	defer attempts.Stop()
	touch := func() { openFromChild(t, allowed) }
	touch()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && !w.sawAllowed {
		select {
		case evt := <-es.Events():
			if evt.Type != event.Openat {
				continue
			}
			path := evt.GetParamAsString(params.FilePath)
			if evt.PID == uint64(os.Getpid()) {
				w.selfOpens++
			}
			if len(w.seen) < cap(w.seen) {
				w.seen = append(w.seen, fmt.Sprintf("pid=%d sys=%d %s",
					evt.PID, evt.GetParamAsUint32(params.SyscallID), path))
			}
			switch path {
			case allowed:
				w.sawAllowed = true
			case deniedPath:
				w.sawDenied = true
			}
		case err := <-es.Errors():
			t.Fatalf("event source error: %v", err)
		case <-attempts.C:
			touch()
		}
	}
	w.rejectsAfter = es.loader.approverRejects()
	return w
}

// openFromChild opens the two paths from a short-lived child rather than from
// the test process. Syscall tracepoints did not report this process's own opens
// on every runner, while child processes are reported reliably, which is also
// how the other privileged tests here drive syscalls.
func openFromChild(t *testing.T, allowed string) {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", "cat -- \"$1\" >/dev/null 2>&1; cat -- \"$2\" >/dev/null 2>&1",
		"sh", allowed, deniedPath)
	_ = cmd.Run()
}

func TestApproverGenerationFlipAndFailedReload(t *testing.T) {
	ldr, err := loadCollections()
	if err != nil {
		t.Fatalf("loading collections: %v", err)
	}
	t.Cleanup(func() { _ = ldr.Close() })

	plan := filter.PlanFromFilter(mustCompile(t, "evt.name = 'openat' and file.path startswith '/tmp'"))
	require.NoError(t, ldr.populateApprovers(plan))
	gen, err := ldr.approverGen()
	require.NoError(t, err)
	require.Equal(t, uint32(1), gen)

	require.NoError(t, ldr.populateApprovers(plan))
	gen, err = ldr.approverGen()
	require.NoError(t, err)
	require.Equal(t, uint32(0), gen)

	oversized := filter.BuildApproverPlan(manyPrefixFilters(t, 300))
	require.Error(t, ldr.populateApprovers(oversized))
	still, err := ldr.approverGen()
	require.NoError(t, err)
	require.Equal(t, gen, still)
}

func mustCompile(t *testing.T, expr string) filter.Filter {
	t.Helper()
	f := filter.New(expr, testConfig())
	require.NoError(t, f.Compile())
	return f
}

func manyPrefixFilters(t *testing.T, n int) []filter.Filter {
	t.Helper()
	out := make([]filter.Filter, 0, n)
	for i := 0; i < n; i++ {
		expr := "evt.name = 'openat' and file.path startswith '" + "/t" + itoa3(i) + "'"
		out = append(out, mustCompile(t, expr))
	}
	return out
}

func itoa3(n int) string {
	return string([]byte{
		byte('0' + (n/100)%10),
		byte('0' + (n/10)%10),
		byte('0' + n%10),
	})
}

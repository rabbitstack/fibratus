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

	cfg := testConfig()
	// Written as a matches pattern rather than startswith so the rewrite into
	// the LPM trie is covered too.
	plan := filter.PlanFromFilter(mustCompile(t,
		"evt.name = 'openat' and file.path matches '"+dir+"/*'"))

	es := NewEventSource(ps.NewSnapshotter(), cfg, nil, plan).(*EventSource)
	require.NoError(t, es.Open(cfg))
	t.Cleanup(func() { _ = es.Close() })

	before := es.loader.approverRejects()
	touch := func(path string) {
		if f, err := os.Open(path); err == nil {
			_ = f.Close()
		}
	}

	// Keep generating attempts while draining. Correlating sys_enter_openat
	// with its exit goes through a bounded LRU map, so on a loaded machine any
	// single open can lose its scratch entry and arrive with no path at all.
	// Retrying makes the assertion about the approver rather than about that.
	attempts := time.NewTicker(100 * time.Millisecond)
	defer attempts.Stop()
	touch(allowed)
	touch("/etc/hostname")

	deadline := time.Now().Add(30 * time.Second)
	var sawAllowed, sawRejectedPath bool
	seen := make([]string, 0, 16)
	for time.Now().Before(deadline) && !sawAllowed {
		select {
		case evt := <-es.Events():
			if evt.Type != event.Openat {
				continue
			}
			path := evt.GetParamAsString(params.FilePath)
			if len(seen) < cap(seen) {
				seen = append(seen, path)
			}
			switch path {
			case allowed:
				sawAllowed = true
			case "/etc/hostname":
				sawRejectedPath = true
			}
		case err := <-es.Errors():
			t.Fatalf("event source error: %v", err)
		case <-attempts.C:
			touch(allowed)
			touch("/etc/hostname")
		}
	}

	require.True(t, sawAllowed,
		"openat matching the approved pattern never reached userspace; wanted %q, saw %q, rejects %d -> %d",
		allowed, seen, before, es.loader.approverRejects())
	require.False(t, sawRejectedPath, "openat outside the approved pattern reached userspace")
	require.Greater(t, es.loader.approverRejects(), before, "approver reject counter did not advance")
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

//go:build linux

/*
 * Copyright 2026 Fibratus contributors
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

package spike

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	libebpf "github.com/rabbitstack/fibratus/internal/ebpf"
)

const (
	eventKindExec     = 1
	eventKindSnapshot = 2
)

// Result summarizes a successful spike run.
type Result struct {
	Prerequisites *libebpf.PrerequisiteReport
	Snapshots     int
	ExecEvents    int
	Reconciled    int
	Metrics       string
}

// Run proves CO-RE load, shared-map replacement, race-safe startup, and
// best-effort /proc enrichment on a real Linux kernel.
func Run(duration time.Duration) (*Result, error) {
	report, err := libebpf.ProbePrerequisites()
	if err != nil {
		return &Result{Prerequisites: report}, fmt.Errorf("prerequisites: %w", err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock: %w", err)
	}

	execSpec, err := loadExecve()
	if err != nil {
		return nil, fmt.Errorf("loading execve collection spec: %w", err)
	}
	iterSpec, err := loadProciter()
	if err != nil {
		return nil, fmt.Errorf("loading prociter collection spec: %w", err)
	}

	var execObjs execveObjects
	if err := execSpec.LoadAndAssign(&execObjs, nil); err != nil {
		return nil, fmt.Errorf("loading execve objects: %w", err)
	}
	defer execObjs.Close()

	// Inject the canonical shared maps from the first collection into the second.
	// The first collection owns those maps; only close the iterator program here.
	var iterObjs prociterObjects
	if err := iterSpec.LoadAndAssign(&iterObjs, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"events":     execObjs.Events,
			"drop_count": execObjs.DropCount,
		},
	}); err != nil {
		return nil, fmt.Errorf("loading prociter with map replacements: %w", err)
	}
	defer func() {
		if iterObjs.DumpTask != nil {
			_ = iterObjs.DumpTask.Close()
		}
	}()

	rd, err := ringbuf.NewReader(execObjs.Events)
	if err != nil {
		return nil, fmt.Errorf("opening ringbuf reader: %w", err)
	}
	defer rd.Close()

	reconciler := libebpf.NewStartupReconciler(4096)
	stop := make(chan struct{})
	done := make(chan struct{})
	var execCount, snapCount atomic.Uint64

	go func() {
		defer close(done)
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				select {
				case <-stop:
					return
				case <-time.After(10 * time.Millisecond):
					continue
				}
			}
			ev, err := parseSpikeEvent(record.RawSample)
			if err != nil {
				continue
			}
			key := libebpf.ProcessKey{PID: ev.Tgid, StartBootTime: ev.StartBoottime}
			comm := cString(ev.Comm[:])
			filename := cString(ev.Filename[:])
			switch ev.Kind {
			case eventKindSnapshot:
				exe, cmdline, enrErr := enrichFromProc(ev.Tgid)
				if enrErr != nil {
					reconciler.AccountEnrichmentMiss()
				}
				snapCount.Add(1)
				reconciler.UpsertSnapshot(libebpf.ProcessRecord{
					Key:      key,
					Comm:     comm,
					Filename: filename,
					ExePath:  exe,
					Cmdline:  cmdline,
				})
			case eventKindExec:
				// Short-lived execs often exit before /proc enrichment; that is expected.
				exe, cmdline, _ := enrichFromProc(ev.Tgid)
				execCount.Add(1)
				_ = reconciler.EnqueueHot(libebpf.HotEvent{
					Key:       key,
					Kind:      ev.Kind,
					Timestamp: ev.TimestampNs,
					Comm:      comm,
					Filename:  filename,
					ExePath:   exe,
					Cmdline:   cmdline,
				})
			}
		}
	}()

	// Attach hot path before running the iterator so events during baseline land in the pending queue.
	tp, err := link.Tracepoint("sched", "sched_process_exec", execObjs.HandleSchedProcessExec, nil)
	if err != nil {
		close(stop)
		_ = rd.Close()
		<-done
		return nil, fmt.Errorf("attaching sched_process_exec: %w", err)
	}
	defer tp.Close()

	it, err := link.AttachIter(link.IterOptions{Program: iterObjs.DumpTask})
	if err != nil {
		close(stop)
		_ = rd.Close()
		<-done
		return nil, fmt.Errorf("attaching iter/task: %w", err)
	}
	defer it.Close()

	// Generate hot traffic while the iterator runs so pending-queue reconciliation is exercised.
	trafficStop := make(chan struct{})
	trafficDone := make(chan struct{})
	go func() {
		defer close(trafficDone)
		for {
			select {
			case <-trafficStop:
				return
			default:
				runTrueOnce()
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()

	file, err := it.Open()
	if err != nil {
		close(trafficStop)
		<-trafficDone
		close(stop)
		_ = rd.Close()
		<-done
		return nil, fmt.Errorf("opening task iterator: %w", err)
	}
	_, _ = io.Copy(io.Discard, file)
	_ = file.Close()

	// Allow in-flight snapshot/hot records to drain, then finish baseline.
	time.Sleep(500 * time.Millisecond)
	close(trafficStop)
	<-trafficDone
	reconciler.FinishBaseline()

	// Generate a little exec traffic and observe live events.
	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		runTrueOnce()
		time.Sleep(50 * time.Millisecond)
	}

	var drop uint64
	var key uint32
	_ = execObjs.DropCount.Lookup(&key, &drop)
	reconciler.AccountRingbufDrop(drop)

	close(stop)
	_ = rd.Close()
	<-done

	return &Result{
		Prerequisites: report,
		Snapshots:     int(snapCount.Load()),
		ExecEvents:    int(execCount.Load()),
		Reconciled:    reconciler.Size(),
		Metrics:       reconciler.Metrics.String(),
	}, nil
}

// FormatReport renders spike diagnostics for humans and CI logs.
func FormatReport(r *Result) string {
	if r == nil {
		return ""
	}
	if r.Prerequisites == nil {
		return fmt.Sprintf("snapshots=%d exec_events=%d reconciled=%d\nmetrics: %s\n",
			r.Snapshots, r.ExecEvents, r.Reconciled, r.Metrics)
	}
	return fmt.Sprintf(
		"kernel=%s btf=%v ringbuf=%v iter=%v\nsnapshots=%d exec_events=%d reconciled=%d\nmetrics: %s\n",
		r.Prerequisites.KernelRelease,
		r.Prerequisites.BTFOK,
		r.Prerequisites.RingbufOK,
		r.Prerequisites.IterOK,
		r.Snapshots,
		r.ExecEvents,
		r.Reconciled,
		r.Metrics,
	)
}

func parseSpikeEvent(raw []byte) (spikeEvent, error) {
	var ev spikeEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
		return ev, err
	}
	return ev, nil
}

func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func execLookPath() string {
	for _, p := range []string{"/bin/true", "/usr/bin/true"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "/bin/sh"
}

func runTrueOnce() {
	cmd := execLookPath()
	p, err := os.StartProcess(cmd, []string{cmd}, &os.ProcAttr{
		Files: []*os.File{nil, nil, nil},
	})
	if err != nil {
		return
	}
	_, _ = p.Wait()
}

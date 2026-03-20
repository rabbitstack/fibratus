/*
 * Copyright 2021-present by Nedim Sabic Sabic
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

package va

import (
	"expvar"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/rabbitstack/fibratus/pkg/sys"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

var (
	workingsetOpsCount     = expvar.NewInt("workingset.ops.count")
	workingsetTimeoutCount = expvar.NewInt("workingset.timeout.count")
)

// jitter dynamically adjust the wait timeout for the worker thread.
type jitter struct {
	p99        time.Duration // 99th percentile observed
	samples    []time.Duration
	maxSamples int
}

// ctx contains all arguments submitted to the QueryWorkingSet API.
type ctx struct {
	proc windows.Handle
	ws   []sys.MemoryWorkingSetExInformation
	size uint32 // byte size of the ws slice
	done uint32 // 1 if completed successfully
}

// worker represents a single reusable native OS thread.
type worker struct {
	in     windows.Handle // caller signals work is ready
	out    windows.Handle // thread signals work is done
	quit   windows.Handle // signals the callback to exit
	h      windows.Handle
	ctx    *ctx // shared work context
	jitter *jitter
}

// pool is a fixed-size pool of native OS threads to query working set regions.
type pool struct {
	workers []*worker
	free    chan *worker
	size    int
}

func (j *jitter) record(d time.Duration) {
	j.samples = append(j.samples, d)
	if len(j.samples) > j.maxSamples {
		j.samples = j.samples[1:]
	}
	// recompute p99
	sorted := append([]time.Duration{}, j.samples...)
	slices.Sort(sorted)
	j.p99 = sorted[int(float64(len(sorted))*0.99)]
}

func (j *jitter) timeout() uint32 {
	if j.p99 == 0 {
		return 100 // default before enough samples
	}
	// timeout = p99 * 3, clamped between 50ms and 500ms
	v := j.p99 * 3
	v = max(v, 50*time.Millisecond)
	v = min(v, 500*time.Millisecond)
	return uint32(v.Milliseconds())
}

var callback = windows.NewCallback(func(param uintptr) uintptr {
	w := (*worker)(unsafe.Pointer(param))

	// wait on both in and quit to never block on INFINITE with a single event
	handles := []windows.Handle{w.in, w.quit}
	for {
		// sleep until caller gives us work
		wait, _ := windows.WaitForMultipleObjects(handles, false, windows.INFINITE)
		switch wait {
		case windows.WAIT_OBJECT_0:
			if err := sys.QueryWorkingSet(w.ctx.proc, &w.ctx.ws[0], w.ctx.size); err == nil {
				atomic.StoreUint32(&w.ctx.done, 1)
			}
			// signal caller that work is complete
			_ = windows.SetEvent(w.out)
		case windows.WAIT_OBJECT_0 + 1: // w.quit signaled so exit cleanly
			return 0
		default:
			return 1
		}
	}
})

func newPool(size int) (*pool, error) {
	p := &pool{
		free: make(chan *worker, size),
		size: size,
	}
	for range size {
		w, err := newWorker()
		if err != nil {
			p.close()
			return nil, err
		}
		p.workers = append(p.workers, w)
		p.free <- w
	}
	return p, nil
}

// acquire grabs a free worker, or returns nil if none available
func (p *pool) acquire(timeout time.Duration) *worker {
	select {
	case w := <-p.free:
		return w
	case <-time.After(timeout):
		return nil
	}
}

// release returns a healthy worker to the pool.
// If the worker is poisoned (stalled), it is evicted and replaced.
func (p *pool) release(w *worker, poisoned bool) {
	if !poisoned {
		// reset events and context for reuse
		_ = windows.ResetEvent(w.in)
		_ = windows.ResetEvent(w.out)
		atomic.StoreUint32(&w.ctx.done, 0)
		p.free <- w
		return
	}

	// evict the stuck thread
	w.close()

	// spawn a replacement asynchronously to keep pool size stable
	go func() {
		replacement, err := newWorker()
		if err != nil {
			// pool shrinks by 1
			log.Warnf("unable to spawn replacement worker: %v", err)
			return
		}
		p.free <- replacement
	}()
}

func (p *pool) close() {
	close(p.free)
	for w := range p.free {
		w.close()
	}
}

func newWorker() (*worker, error) {
	w := &worker{
		ctx:    &ctx{},
		jitter: &jitter{maxSamples: 1000},
	}

	var err error
	w.in, err = windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return nil, err
	}
	w.out, err = windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		_ = windows.CloseHandle(w.out)
		return nil, err
	}
	w.quit, err = windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		_ = windows.CloseHandle(w.in)
		_ = windows.CloseHandle(w.out)
		return nil, err
	}

	w.h = sys.CreateThread(
		nil,
		0,
		callback,
		uintptr(unsafe.Pointer(w)),
		0,
		nil)
	if w.h == 0 {
		w.close()
		return nil, err
	}

	return w, nil
}

func (w *worker) close() {
	if w.quit != 0 {
		// signal the callback to exit gracefully first
		_ = windows.SetEvent(w.quit)
		// give it a moment to exit before forcing termination
		if w.h != 0 {
			if wait, _ := windows.WaitForSingleObject(w.h, 200); wait != windows.WAIT_OBJECT_0 {
				_ = sys.TerminateThread(w.h, 0) // last resort
			}
		}
	}
	if w.h != 0 {
		_ = sys.TerminateThread(w.h, 0)
		_ = windows.CloseHandle(w.h)
	}
	if w.in != 0 {
		_ = windows.CloseHandle(w.in)
	}
	if w.out != 0 {
		_ = windows.CloseHandle(w.out)
	}
	if w.quit != 0 {
		_ = windows.CloseHandle(w.quit)
	}
}

func (w *worker) submit(proc windows.Handle, ws []sys.MemoryWorkingSetExInformation) {
	size := uint32(len(ws)) * uint32(unsafe.Sizeof(sys.MemoryWorkingSetExInformation{}))
	w.ctx.proc = proc
	w.ctx.size = size
	w.ctx.ws = ws
	_ = windows.SetEvent(w.in)
}

func (w *worker) wait() (uint32, error) {
	return windows.WaitForSingleObject(w.out, w.jitter.timeout())
}

func poolSize() int {
	n := runtime.NumCPU() / 2
	if n < 2 {
		return 2
	}
	if n > 8 {
		return 8
	}
	return n
}

var p *pool
var poolOnce sync.Once

// QueryWorkingSet returns working set information for a set of addresses.
func QueryWorkingSet(proc windows.Handle, ws []sys.MemoryWorkingSetExInformation) []sys.MemoryWorkingSetExInformation {
	poolOnce.Do(func() {
		var err error
		p, err = newPool(poolSize())
		if err != nil {
			log.Errorf("unable to create working set pool: %v", err)
		}
	})

	if p == nil {
		return nil
	}

	// acquire a worker and don't wait forever if pool is exhausted
	w := p.acquire(50 * time.Millisecond)
	if w == nil {
		return nil // pool exhausted
	}

	// post work to the thread
	w.submit(proc, ws)

	// wait for completion
	start := time.Now()
	wait, err := w.wait()
	if err != nil {
		return nil
	}

	switch wait {
	case windows.WAIT_OBJECT_0:
		workingsetOpsCount.Add(1)
		// feed successful durations back
		w.jitter.record(time.Since(start))
		defer p.release(w, false)

		if atomic.LoadUint32(&w.ctx.done) == 0 {
			return nil
		}
		return w.ctx.ws

	case sys.WaitTimeout:
		workingsetTimeoutCount.Add(1)
		// thread is stalled inside the kernel syscall.
		// Safe to terminate: no user-mode locks held,
		// no Go runtime state to corrupt.
		p.release(w, true)
		return nil

	default:
		p.release(w, true)
		return nil
	}
}

//go:build windows

package va

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/rabbitstack/fibratus/pkg/sys"
	"golang.org/x/sys/windows"
)

func TestJitterDefaultTimeout(t *testing.T) {
	j := &jitter{maxSamples: 10}
	// no samples recorded yet
	got := j.timeout()
	if got != 100 {
		t.Fatalf("expected default timeout 100ms, got %d", got)
	}
}

func TestJitterTimeoutClampedToMinimum(t *testing.T) {
	j := &jitter{maxSamples: 10}
	// record very short durations to p99*3 would be below 50ms floor
	for i := 0; i < 10; i++ {
		j.record(1 * time.Millisecond)
	}
	got := j.timeout()
	if got < 50 {
		t.Fatalf("timeout %dms is below minimum 50ms", got)
	}
}

func TestJitterTimeoutClampedToMaximum(t *testing.T) {
	j := &jitter{maxSamples: 10}
	// record very long durations (p99*3 would exceed 500ms ceiling)
	for i := 0; i < 10; i++ {
		j.record(1 * time.Second)
	}
	got := j.timeout()
	if got > 500 {
		t.Fatalf("timeout %dms exceeds maximum 500ms", got)
	}
}

func TestJitterTimeoutScalesWithP99(t *testing.T) {
	j := &jitter{maxSamples: 100}
	// record 99 short samples and 1 long outlier
	for i := 0; i < 99; i++ {
		j.record(10 * time.Millisecond)
	}
	j.record(80 * time.Millisecond) // the p99 outlier

	got := j.timeout()
	if got < 50 || got > 500 {
		t.Fatalf("timeout %dms out of expected range [50, 500]", got)
	}
	// should be noticeably larger than the default 100ms
	if got <= 100 {
		t.Fatalf("timeout %dms should reflect the p99 outlier, expected > 100ms", got)
	}
}

func TestJitterSampleWindowIsBounded(t *testing.T) {
	max := 5
	j := &jitter{maxSamples: max}
	// flood with more samples than the window allows
	for i := 0; i < max*3; i++ {
		j.record(time.Duration(i) * time.Millisecond)
	}

	if len(j.samples) > max {
		t.Fatalf("sample buffer grew beyond maxSamples: got %d, want <= %d", len(j.samples), max)
	}
}

func TestJitterConcurrentRecordAndTimeout(t *testing.T) {
	j := &jitter{maxSamples: 100}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(d time.Duration) {
			defer wg.Done()
			j.record(d)
		}(time.Duration(i) * time.Millisecond)
		go func() {
			defer wg.Done()
			j.timeout() // must not race or panic
		}()
	}
	wg.Wait()
}

func TestPoolSizeMinimum(t *testing.T) {
	// regardless of CPU count the pool must be at least 2
	got := poolSize()
	if got < 2 {
		t.Fatalf("poolSize returned %d, want >= 2", got)
	}
}

func TestPoolSizeMaximum(t *testing.T) {
	got := poolSize()
	if got > 8 {
		t.Fatalf("poolSize returned %d, want <= 8", got)
	}
}

func TestPoolSizeIsHalfCPU(t *testing.T) {
	got := poolSize()
	half := runtime.NumCPU() / 2
	// clamp to [2, 8] as the implementation does
	if half < 2 {
		half = 2
	}
	if half > 8 {
		half = 8
	}
	if got != half {
		t.Fatalf("poolSize = %d, want %d (half of %d CPUs, clamped)", got, half, runtime.NumCPU())
	}
}

func TestNewWorkerCreatesValidHandles(t *testing.T) {
	w, err := newWorker()
	if err != nil {
		t.Fatalf("newWorker failed: %v", err)
	}
	defer w.close()

	if w.h == 0 {
		t.Error("thread handle is zero")
	}
	if w.in == 0 {
		t.Error("input event handle is zero")
	}
	if w.out == 0 {
		t.Error("output event handle is zero")
	}
	if w.ctx == nil {
		t.Error("ctx is nil")
	}
	if w.jitter == nil {
		t.Error("jitter is nil")
	}
}

func TestWorkerCloseIsIdempotent(t *testing.T) {
	w, err := newWorker()
	if err != nil {
		t.Fatalf("newWorker failed: %v", err)
	}
	// closing twice must not panic or crash
	w.close()
	w.close()
}

func TestWorkerSubmitSetsContext(t *testing.T) {
	w, err := newWorker()
	if err != nil {
		t.Fatalf("newWorker failed: %v", err)
	}
	defer w.close()

	ws := make([]sys.MemoryWorkingSetExInformation, 2)
	ws[0].VirtualAddress = 0x1000
	ws[1].VirtualAddress = 0x2000

	proc := windows.CurrentProcess()
	w.submit(proc, ws)

	if w.ctx.proc != proc {
		t.Error("ctx.proc not set correctly")
	}
	expectedSize := uint32(2) * uint32(unsafe.Sizeof(sys.MemoryWorkingSetExInformation{}))
	if w.ctx.size != expectedSize {
		t.Errorf("ctx.size = %d, want %d", w.ctx.size, expectedSize)
	}
}

func TestNewPoolCreatesCorrectNumberOfWorkers(t *testing.T) {
	size := 3
	p, err := newPool(size)
	if err != nil {
		t.Fatalf("newPool failed: %v", err)
	}
	defer p.close()

	if len(p.workers) != size {
		t.Errorf("worker count = %d, want %d", len(p.workers), size)
	}
	if cap(p.free) != size {
		t.Errorf("free channel capacity = %d, want %d", cap(p.free), size)
	}
}

func TestPoolAcquireReturnsWorker(t *testing.T) {
	p, err := newPool(2)
	if err != nil {
		t.Fatalf("newPool failed: %v", err)
	}
	defer p.close()

	w := p.acquire(50 * time.Millisecond)
	if w == nil {
		t.Fatal("acquire returned nil but pool has free workers")
	}
}

func TestPoolAcquireReturnsNilWhenExhausted(t *testing.T) {
	p, err := newPool(2)
	if err != nil {
		t.Fatalf("newPool failed: %v", err)
	}
	defer p.close()

	// drain all workers
	w1 := p.acquire(50 * time.Millisecond)
	w2 := p.acquire(50 * time.Millisecond)
	if w1 == nil || w2 == nil {
		t.Fatal("expected to acquire both workers")
	}

	// pool is now empty so must return nil within timeout
	start := time.Now()
	w3 := p.acquire(50 * time.Millisecond)
	elapsed := time.Since(start)

	if w3 != nil {
		t.Error("expected nil from exhausted pool, got a worker")
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("acquire blocked for %v, expected ~50ms timeout", elapsed)
	}
}

func TestPoolReleaseHealthyWorkerReturnsItToPool(t *testing.T) {
	p, err := newPool(2)
	if err != nil {
		t.Fatalf("newPool failed: %v", err)
	}
	defer p.close()

	w := p.acquire(50 * time.Millisecond)
	if w == nil {
		t.Fatal("acquire returned nil")
	}

	p.release(w, false)

	// worker should be back in the pool
	w2 := p.acquire(50 * time.Millisecond)
	if w2 == nil {
		t.Fatal("expected to re-acquire released worker")
	}
}

func TestPoolReleaseHealthyWorkerResetsContext(t *testing.T) {
	p, err := newPool(1)
	if err != nil {
		t.Fatalf("newPool failed: %v", err)
	}
	defer p.close()

	w := p.acquire(50 * time.Millisecond)
	if w == nil {
		t.Fatal("acquire returned nil")
	}
	// simulate completed work
	atomic.StoreUint32(&w.ctx.done, 1)

	p.release(w, false)

	// re-acquire and verify done flag is cleared
	w2 := p.acquire(50 * time.Millisecond)
	if w2 == nil {
		t.Fatal("re-acquire failed")
	}
	if atomic.LoadUint32(&w2.ctx.done) != 0 {
		t.Error("ctx.done was not reset on release")
	}
}

func TestPoolReleasePoisonedWorkerSpawnsReplacement(t *testing.T) {
	p, err := newPool(1)
	if err != nil {
		t.Fatalf("newPool failed: %v", err)
	}
	defer p.close()

	w := p.acquire(50 * time.Millisecond)
	if w == nil {
		t.Fatal("acquire returned nil")
	}

	// evict as poisoned
	p.release(w, true)

	// wait for the replacement goroutine to put a new worker in the pool
	replacement := p.acquire(2 * time.Second)
	if replacement == nil {
		t.Fatal("replacement worker was not added to pool after eviction")
	}
}

func TestPoolConcurrentAcquireRelease(t *testing.T) {
	p, err := newPool(4)
	if err != nil {
		t.Fatalf("newPool failed: %v", err)
	}
	defer p.close()

	var wg sync.WaitGroup
	var acquired atomic.Int32

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := p.acquire(100 * time.Millisecond)
			if w == nil {
				return
			}
			acquired.Add(1)
			time.Sleep(5 * time.Millisecond) // simulate work
			p.release(w, false)
		}()
	}

	wg.Wait()
	if acquired.Load() == 0 {
		t.Error("no workers were ever acquired")
	}
}

func TestQueryWorkingSetCurrentProcess(t *testing.T) {
	// allocate a page so we have a known committed address to query
	const size = 4096
	addr, err := windows.VirtualAlloc(0, size, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		t.Fatalf("VirtualAlloc failed: %v", err)
	}
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)

	ws := []sys.MemoryWorkingSetExInformation{
		{VirtualAddress: addr},
	}

	result := QueryWorkingSet(windows.CurrentProcess(), ws)
	if result == nil {
		t.Fatal("QueryWorkingSet returned nil for a valid committed page")
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result))
	}
}

func TestQueryWorkingSetBatchAddresses(t *testing.T) {
	const pageSize = 4096
	const pages = 8

	addr, err := windows.VirtualAlloc(0, pageSize*pages, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		t.Fatalf("VirtualAlloc failed: %v", err)
	}
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)

	ws := make([]sys.MemoryWorkingSetExInformation, pages)
	for i := range ws {
		ws[i].VirtualAddress = addr + uintptr(i*pageSize)
	}

	result := QueryWorkingSet(windows.CurrentProcess(), ws)
	if result == nil {
		t.Fatal("QueryWorkingSet returned nil for batch of valid pages")
	}
	if len(result) != pages {
		t.Fatalf("expected %d results, got %d", pages, len(result))
	}
}

func TestQueryWorkingSetNilOnNilPool(t *testing.T) {
	// temporarily nil the pool to simulate init failure
	saved := p
	p = nil
	defer func() { p = saved }()

	ws := []sys.MemoryWorkingSetExInformation{{VirtualAddress: 0x1000}}
	result := QueryWorkingSet(windows.CurrentProcess(), ws)
	if result != nil {
		t.Error("expected nil result when pool is nil")
	}
}

func TestQueryWorkingSetPoolExhaustion(t *testing.T) {
	// create a tiny pool and exhaust it
	tiny, err := newPool(1)
	if err != nil {
		t.Fatalf("newPool failed: %v", err)
	}
	defer tiny.close()

	saved := p
	p = tiny
	defer func() { p = saved }()

	// hold the only worker
	held := tiny.acquire(50 * time.Millisecond)
	if held == nil {
		t.Fatal("could not acquire the only worker")
	}
	defer tiny.release(held, false)

	// now QueryWorkingSet should fail gracefully
	ws := []sys.MemoryWorkingSetExInformation{{VirtualAddress: 0x1000}}
	result := QueryWorkingSet(windows.CurrentProcess(), ws)
	if result != nil {
		t.Error("expected nil when pool is exhausted")
	}
}

func TestQueryWorkingSetPoolSingletonInit(t *testing.T) {
	// reset the singleton so poolOnce triggers again
	poolOnce = sync.Once{}
	p = nil

	ws := []sys.MemoryWorkingSetExInformation{{VirtualAddress: 0x1000}}
	// just ensure the lazy init path doesn't panic
	_ = QueryWorkingSet(windows.CurrentProcess(), ws)

	if p == nil {
		t.Error("pool was not initialized by QueryWorkingSet")
	}
}

func TestQueryWorkingSetConcurrentCalls(t *testing.T) {
	const pageSize = 4096
	addr, err := windows.VirtualAlloc(0, pageSize, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		t.Fatalf("VirtualAlloc failed: %v", err)
	}
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)

	var wg sync.WaitGroup
	var successCount atomic.Int32

	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ws := []sys.MemoryWorkingSetExInformation{{VirtualAddress: addr}}
			if QueryWorkingSet(windows.CurrentProcess(), ws) != nil {
				successCount.Add(1)
			}
		}()
	}

	wg.Wait()
	// with a pool of poolSize() workers, some calls will be dropped under
	// contention but at least some must succeed
	if successCount.Load() == 0 {
		t.Error("all concurrent QueryWorkingSet calls failed")
	}
}

func BenchmarkQueryWorkingSetSinglePage(b *testing.B) {
	const pageSize = 4096
	addr, err := windows.VirtualAlloc(0, pageSize, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		b.Fatalf("VirtualAlloc failed: %v", err)
	}
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)

	ws := []sys.MemoryWorkingSetExInformation{{VirtualAddress: addr}}
	proc := windows.CurrentProcess()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		QueryWorkingSet(proc, ws)
	}
}

func BenchmarkQueryWorkingSetBatch64Pages(b *testing.B) {
	const pageSize = 4096
	const pages = 64

	addr, err := windows.VirtualAlloc(0, pageSize*pages, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		b.Fatalf("VirtualAlloc failed: %v", err)
	}
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)

	ws := make([]sys.MemoryWorkingSetExInformation, pages)
	for i := range ws {
		ws[i].VirtualAddress = addr + uintptr(i*pageSize)
	}
	proc := windows.CurrentProcess()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		QueryWorkingSet(proc, ws)
	}
}

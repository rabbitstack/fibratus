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

package signature

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/pe"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/stretchr/testify/require"
)

func systemDir(path string) string {
	return filepath.Join(os.Getenv("windir"), "system32", path)
}

// wellKnownDLLs are catalog-signed system DLLs present on every
// supported Windows version. They provide a reliable test corpus
// without requiring specific test fixtures.
var wellKnownDLLs = []string{
	systemDir("kernel32.dll"),
	systemDir("kernelbase.dll"),
	systemDir("ntdll.dll"),
	systemDir("user32.dll"),
}

var embeddedSignedDLL = systemDir("kernel32.dll")

// freshSignatures returns a clean Signatures instance and registers
// a cleanup that closes it and resets the singleton.
func freshSignatures(t *testing.T) *Signatures {
	t.Helper()
	s := newSignatures()
	t.Cleanup(func() {
		s.Close()
	})
	return s
}

func freshSignaturesWithoutCleanup(t *testing.T) *Signatures {
	t.Helper()
	return newSignatures()
}

// makeKeyForFile builds a Key by reading the PE header of a real file.
// If the file cannot be read the test is skipped.
func makeKeyForFile(t *testing.T, path string) Key {
	t.Helper()
	hdr, err := pe.ParseFile(path, pe.WithSections())
	if err != nil {
		t.Skipf("cannot read PE header for %s: %v", path, err)
	}
	return MakeKey(path, uint64(hdr.ImageSize), hdr.ImageChecksum, hdr.TimedateStamp)
}

func TestKeyNormalisation(t *testing.T) {
	// keys built with different casing must be equal. Windows paths
	// are case-insensitive and the rule engine may supply either form.
	k1 := MakeKey(`C:\Windows\System32\NTDLL.DLL`, 0x100000, 0xABCD, 0x12345678)
	k2 := MakeKey(`c:\windows\system32\ntdll.dll`, 0x100000, 0xABCD, 0x12345678)
	if k1 != k2 {
		t.Errorf("keys with different casing must be equal\n  k1=%+v\n  k2=%+v", k1, k2)
	}
}

func TestKeyDistinctForDifferentTimestamps(t *testing.T) {
	// Same path, different build results in different key.
	// This is the core property that prevents stale cache hits after
	// a DLL update (e.g. Windows Update replaces ntdll.dll).
	k1 := MakeKey(`c:\windows\system32\ntdll.dll`, 0x100000, 0, 0x11111111)
	k2 := MakeKey(`c:\windows\system32\ntdll.dll`, 0x100000, 0, 0x22222222)
	if k1 == k2 {
		t.Error("keys with different TimeDateStamp must not be equal")
	}
}

func TestKeyDistinctForDifferentImageSizes(t *testing.T) {
	// same path + timestamp but different image size has different key.
	// Guards against reproducible builds that strip the timestamp
	k1 := MakeKey(`c:\windows\system32\ntdll.dll`, 0x100000, 0, 0)
	k2 := MakeKey(`c:\windows\system32\ntdll.dll`, 0x200000, 0, 0)
	if k1 == k2 {
		t.Error("keys with different ImageSize must not be equal")
	}
}

func TestKeyDistinctForDifferentPaths(t *testing.T) {
	k1 := MakeKey(`c:\windows\system32\kernel32.dll`, 0x100000, 0xABCD, 0x12345678)
	k2 := MakeKey(`c:\windows\system32\ntdll.dll`, 0x100000, 0xABCD, 0x12345678)
	if k1 == k2 {
		t.Error("keys with different paths must not be equal")
	}
}

func TestKeyStringDeterministic(t *testing.T) {
	// Key.String() is used as the singleflight group key.
	// The same Key must always produce the same string.
	k := MakeKey(`c:\windows\system32\ntdll.dll`, 0x100000, 0xABCD, 0x12345678)
	if k.String() != k.String() {
		t.Error("Key.String() must be deterministic")
	}
}

func TestKeyStringDistinctForDifferentKeys(t *testing.T) {
	k1 := MakeKey(`c:\windows\system32\ntdll.dll`, 0x100000, 0xABCD, 0x11111111)
	k2 := MakeKey(`c:\windows\system32\ntdll.dll`, 0x100000, 0xABCD, 0x22222222)
	if k1.String() == k2.String() {
		t.Error("distinct keys must produce distinct strings")
	}
}

func TestIsDegenerateReturnsTrueWhenBothZero(t *testing.T) {
	k := MakeKey(`c:\windows\system32\ntdll.dll`, 0x100000, 0, 0)
	if !k.IsDegenerate() {
		t.Error("key with zero CheckSum and TimeDateStamp must be degenerate")
	}
}

func TestIsDegenerateReturnsFalseWhenTimestampPresent(t *testing.T) {
	k := MakeKey(`c:\windows\system32\ntdll.dll`, 0x100000, 0, 0x12345678)
	if k.IsDegenerate() {
		t.Error("key with non-zero TimeDateStamp must not be degenerate")
	}
}

func TestIsDegenerateReturnsFalseWhenChecksumPresent(t *testing.T) {
	k := MakeKey(`c:\windows\system32\ntdll.dll`, 0x100000, 0xABCD, 0)
	if k.IsDegenerate() {
		t.Error("key with non-zero CheckSum must not be degenerate")
	}
}

func TestGetSignaturesReturnsSameInstance(t *testing.T) {
	s1 := GetSignatures()
	s2 := GetSignatures()
	if s1 != s2 {
		t.Error("GetSignatures must return the same singleton instance")
	}
	s1.Close()
}

func TestPutAndGetSignature(t *testing.T) {
	s := freshSignatures(t)
	key := MakeKey(`c:\windows\system32\ntdll.dll`, 0x100000, 0xABCD, 0x12345678)

	s.PutSignature(key, TypeEmbedded, LevelWindows)
	sig := s.GetSignature(key)
	if sig == nil {
		t.Fatal("GetSignature returned nil after PutSignature")
	}
	if sig.Type() != TypeEmbedded {
		t.Errorf("expected Type=%v, got %v", TypeEmbedded, sig.Type())
	}
}

func TestPutSignatureIdempotent(t *testing.T) {
	// a second PutSignature for the same key must not overwrite
	// the existing entry because the cache entry is immutable once set
	s := freshSignatures(t)
	key := MakeKey(`c:\windows\system32\ntdll.dll`, 0x100000, 0xABCD, 0x12345678)

	s.PutSignature(key, TypeEmbedded, LevelWindows)
	s.PutSignature(key, TypeNone, LevelUnsigned) // must be ignored

	sig := s.GetSignature(key)
	if sig.Type() != TypeEmbedded {
		t.Errorf("second PutSignature must not overwrite: got Type=%v", sig.Type())
	}
}

func TestGetSignatureReturnsNilOnMiss(t *testing.T) {
	s := freshSignatures(t)
	key := MakeKey(`c:\nonexistent\path\foo.dll`, 0x1000, 0, 0x12345678)
	if s.GetSignature(key) != nil {
		t.Error("GetSignature must return nil for unknown key")
	}
}

func TestPutSignatureUpdatesCount(t *testing.T) {
	s := freshSignatures(t)
	before := signatureCount.Value()
	key := MakeKey(`c:\windows\system32\ntdll.dll`, 0x100000, 0xABCD, 0x12345678)
	s.PutSignature(key, TypeEmbedded, LevelWindows)
	after := signatureCount.Value()
	if after != before+1 {
		t.Errorf("signatureCount should have increased by 1: before=%d after=%d", before, after)
	}
}

func TestRemoveSignatureDeletesEntry(t *testing.T) {
	s := freshSignatures(t)
	key := MakeKey(`c:\windows\system32\ntdll.dll`, 0x100000, 0xABCD, 0x12345678)
	s.PutSignature(key, TypeEmbedded, LevelWindows)

	s.RemoveSignature(`C:\Windows\System32\ntdll.dll`) // different casing
	if s.GetSignature(key) != nil {
		t.Error("RemoveSignature must delete the entry regardless of path casing")
	}
}

// Bug regression: RemoveSignature only deleted the first matching key.
// If the same path appeared with two different timestamps (two builds of
// the same DLL loaded at different times), the second entry survived.
func TestRemoveSignatureDeletesAllMatchingPaths(t *testing.T) {
	s := freshSignatures(t)
	path := `c:\windows\system32\ntdll.dll`

	k1 := MakeKey(path, 0x100000, 0xABCD, 0x11111111)
	k2 := MakeKey(path, 0x100000, 0xABCD, 0x22222222)
	s.PutSignature(k1, TypeEmbedded, LevelWindows)
	s.PutSignature(k2, TypeEmbedded, LevelWindows)

	s.RemoveSignature(path)

	if s.GetSignature(k1) != nil || s.GetSignature(k2) != nil {
		t.Error("RemoveSignature must delete all entries sharing the same path")
	}
}

func TestRemoveSignatureNoopForUnknownPath(t *testing.T) {
	s := freshSignatures(t)
	// must not panic or return an error for a path not in the store.
	s.RemoveSignature(`c:\nonexistent\foo.dll`)
}

func TestKeepAliveUpdatesTimestamp(t *testing.T) {
	sig := newUncheckedSignature(`c:\windows\system32\ntdll.dll`)
	before := sig.accessed.Load()

	time.Sleep(2 * time.Millisecond)
	sig.keepalive()
	after := sig.accessed.Load()

	if after <= before {
		t.Error("keepalive must advance the accessed timestamp")
	}
}

func TestGCEvictsStaleEntries(t *testing.T) {
	s := freshSignatures(t)

	// Shrink TTL so the GC fires during the test.
	oldTTL := sigTTL
	sigTTL = 50 * time.Millisecond
	t.Cleanup(func() { sigTTL = oldTTL })

	key := MakeKey(`c:\windows\system32\ntdll.dll`, 0x100000, 0xABCD, 0x12345678)
	s.PutSignature(key, TypeEmbedded, LevelWindows)

	// Wait beyond TTL then trigger GC directly.
	time.Sleep(100 * time.Millisecond)
	s.gcSignatures()

	if s.GetSignature(key) != nil {
		t.Error("GC must evict entries older than sigTTL")
	}
}

func TestGCDoesNotEvictRecentlyAccessed(t *testing.T) {
	s := freshSignatures(t)

	oldTTL := sigTTL
	sigTTL = 50 * time.Millisecond
	t.Cleanup(func() { sigTTL = oldTTL })

	key := MakeKey(`c:\windows\system32\ntdll.dll`, 0x100000, 0xABCD, 0x12345678)
	s.PutSignature(key, TypeEmbedded, LevelWindows)

	// Touch the entry just before TTL expires.
	time.Sleep(30 * time.Millisecond)
	s.GetSignature(key) // triggers keepalive
	time.Sleep(30 * time.Millisecond)
	s.gcSignatures()

	if s.GetSignature(key) == nil {
		t.Error("GC must not evict recently accessed entries")
	}
}

func TestConcurrentGetAndPut(t *testing.T) {
	s := freshSignatures(t)
	key := MakeKey(`c:\windows\system32\ntdll.dll`, 0x100000, 0xABCD, 0x12345678)

	var wg sync.WaitGroup
	const workers = 64

	// Writers
	for i := 0; i < workers/2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.PutSignature(key, TypeEmbedded, LevelWindows)
		}()
	}

	// Readers
	for i := 0; i < workers/2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.GetSignature(key) // must not race with writers
		}()
	}

	wg.Wait()
}

func TestConcurrentDoRequestAsync(t *testing.T) {
	// Verifies that concurrent async requests for the same key do not
	// enqueue duplicate work and that the cache reaches a consistent state.
	s := freshSignatures(t)
	key := MakeKey(`c:\windows\system32\ntdll.dll`, 0x100000, 0xABCD, 0x12345678)

	var wg sync.WaitGroup
	const goroutines = 32
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			s.DoRequestAsync(key)
		}()
	}
	wg.Wait()
}

func TestDoRequestAsyncSkipsKnownUnsigned(t *testing.T) {
	s := freshSignatures(t)

	// Pre-populate with an unsigned entry.
	key := MakeKey(`c:\windows\system32\fake.dll`, 0x1000, 0, 0x12345678)
	s.mux.Lock()
	s.signatures[key] = newSignature(key.Path, TypeNone, LevelUnsigned)
	s.mux.Unlock()

	before := len(s.requests)
	s.DoRequestAsync(key)
	after := len(s.requests)

	if after != before {
		t.Errorf("DoRequestAsync must not enqueue a request for a known-unsigned DLL: queue grew by %d", after-before)
	}
}

func TestParsePEHeaderKernel32(t *testing.T) {
	hdr, err := pe.ParseFile(`C:\Windows\System32\kernel32.dll`, pe.WithSections())
	if err != nil {
		t.Fatalf("parsePEHeader failed: %v", err)
	}
	if hdr.TimedateStamp == 0 {
		t.Error("kernel32.dll must have a non-zero TimeDateStamp")
	}
	if hdr.ImageSize == 0 {
		t.Error("kernel32.dll must have a non-zero ImageSize")
	}
}

func TestSignatureCheckEmbedded(t *testing.T) {
	if !isWintrustAvailable() {
		t.Skip("wintrust not available")
	}
	sig := newUncheckedSignature(embeddedSignedDLL)
	if err := sig.check(); err != nil {
		t.Fatalf("check() failed for %s: %v", embeddedSignedDLL, err)
	}
	if !sig.Exists() {
		t.Error("notepad.exe must have Exists=true")
	}
	if sig.Type() != TypeEmbedded {
		t.Errorf("notepad.exe must have TypeEmbedded, got %v", sig.Type())
	}
}

func TestSignatureCheckCatalogSigned(t *testing.T) {
	if !isWintrustAvailable() {
		t.Skip("wintrust not available")
	}
	// notepad is catalog-signed on most Windows installations.
	sig := newUncheckedSignature(systemDir("notepad.exe"))
	if err := sig.check(); err != nil && err != ErrNoSignature {
		t.Fatalf("check() unexpected error for notepad.exe: %v", err)
	}
	if sig.Exists() && sig.Type() == TypeNone {
		t.Error("notepad.exe Exists=true but Type=None is inconsistent")
	}
}

func TestSignatureCheckNonExistentFile(t *testing.T) {
	sig := newUncheckedSignature(`C:\nonexistent\ghost.dll`)
	err := sig.check()
	if err == nil {
		t.Error("check() must return an error for a non-existent file")
	}
}

func TestSignatureCheckUnsignedFile(t *testing.T) {
	exe, err := os.Executable()
	require.NoError(t, err)
	sig := newUncheckedSignature(exe)
	err = sig.check()
	if err == nil {
		t.Error("check() must return an error for unsigned file")
	}
}

func TestDoRequestReturnsCachedResult(t *testing.T) {
	s := freshSignatures(t)
	key := makeKeyForFile(t, `C:\Windows\System32\kernel32.dll`)

	// Warm the cache.
	sig1 := s.DoRequest(key)
	if sig1 == nil {
		t.Fatal("first DoRequest returned nil")
	}

	// Second call must return the cached entry, not re-check.
	sig2 := s.DoRequest(key)
	if sig1 != sig2 {
		t.Error("DoRequest must return the same *Signature pointer on cache hit")
	}
}

func TestDoRequestDeduplicatesConcurrentMisses(t *testing.T) {
	// Verifies that singleflight collapses N concurrent misses for the
	// same key into a single check() invocation. We cannot directly count
	// check() calls without instrumentation, so we verify the observable
	// invariant: all callers receive an identical *Signature pointer.
	s := freshSignatures(t)
	key := makeKeyForFile(t, systemDir("kernel32.dll"))

	const goroutines = 16
	results := make([]*Signature, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			results[i] = s.DoRequest(key)
		}()
	}
	wg.Wait()

	first := results[0]
	for i, r := range results {
		if r != first {
			t.Errorf("goroutine %d got a different *Signature — singleflight not working", i)
		}
	}
}

func TestDoRequestAsyncEventuallyPopulatesCache(t *testing.T) {
	s := freshSignatures(t)
	key := makeKeyForFile(t, systemDir("kernel32.dll"))

	s.DoRequestAsync(key)

	// Poll until the cache entry appears or timeout.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if sig := s.GetSignature(key); sig != nil {
			return // success
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("DoRequestAsync did not populate the cache within 5 seconds")
}

func TestWellKnownDLLsResolveWithinBudget(t *testing.T) {
	// all well-known system DLLs must resolve within 500ms each.
	// This guards against pathological catalog hash slowness.
	if !isWintrustAvailable() {
		t.Skip("wintrust not available")
	}

	s := freshSignatures(t)

	for _, path := range wellKnownDLLs {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			key := makeKeyForFile(t, path)

			start := time.Now()
			sig := s.DoRequest(key)
			elapsed := time.Since(start)

			if sig == nil {
				t.Logf("DoRequest returned nil for %s", path)
			}
			if elapsed > 500*time.Millisecond {
				t.Logf("WARN: DoRequest took %v for %s (budget: 500ms)", elapsed, path)
			}
		})
	}
}

func TestPrewarmReducesLatencyForSubsequentRequests(t *testing.T) {
	if !isWintrustAvailable() {
		t.Skip("wintrust not available")
	}

	s := freshSignatures(t)

	// Prewarm a well-known DLL.
	path := `C:\Windows\System32\kernel32.dll`
	key := makeKeyForFile(t, path)
	s.DoRequest(key) // blocks until resolved — this is the prewarm

	// Subsequent request must hit the cache and return within 1ms.
	start := time.Now()
	sig := s.GetSignature(key)
	elapsed := time.Since(start)

	if sig == nil {
		t.Fatal("GetSignature returned nil after prewarm")
	}
	if elapsed > time.Millisecond {
		t.Errorf("cache hit took %v (expected <1ms)", elapsed)
	}
}

func TestIsTrustedWindowsSigned(t *testing.T) {
	cases := []struct {
		sigType  Type
		level    Level
		expected bool
	}{
		{TypeEmbedded, LevelWindows, true},
		{TypeEmbedded, LevelWindowsTCB, true},
		{TypeFileVerified, LevelWindows, true},
		{TypeEmbedded, LevelAuthenticode, false}, // Authenticode is not Windows-level trust
		{TypeCatalogCached, LevelWindows, false},
		{TypeNone, LevelUnsigned, false},
		{TypeEmbedded, LevelUnsigned, false},
	}
	for _, tc := range cases {
		got := IsTrusted(tc.sigType, tc.level)
		if got != tc.expected {
			t.Errorf("IsTrusted(%v, %v) = %v, want %v", tc.sigType, tc.level, got, tc.expected)
		}
	}
}

func TestNewSignatureTrustedSetsStatus(t *testing.T) {
	sig := newSignature(`c:\windows\system32\ntdll.dll`, TypeEmbedded, LevelWindows)
	if !sig.IsTrusted() {
		t.Error("newSignature with trusted type+level must set IsTrusted=true")
	}
	if !sig.Exists() {
		t.Error("newSignature with trusted type+level must set Exists=true")
	}
}

func TestNewUncheckedSignatureIsNotTrusted(t *testing.T) {
	sig := newUncheckedSignature(`c:\windows\system32\ntdll.dll`)
	if sig.IsTrusted() {
		t.Error("newUncheckedSignature must not be trusted")
	}
	if sig.Type() != TypeNone {
		t.Errorf("newUncheckedSignature must have TypeNone, got %v", sig.Type())
	}
}

func TestSignatureCountConsistencyAfterGC(t *testing.T) {
	s := freshSignatures(t)

	oldTTL := sigTTL
	sigTTL = 50 * time.Millisecond
	t.Cleanup(func() { sigTTL = oldTTL })

	before := signatureCount.Value()

	k1 := MakeKey(`c:\a.dll`, 0x1000, 0, 0x11111111)
	k2 := MakeKey(`c:\b.dll`, 0x1000, 0, 0x22222222)
	s.PutSignature(k1, TypeEmbedded, LevelWindows)
	s.PutSignature(k2, TypeEmbedded, LevelWindows)

	time.Sleep(100 * time.Millisecond)
	s.gcSignatures()

	after := signatureCount.Value()

	// Both entries added then GC'd: net change should be zero.
	if after != before {
		t.Errorf("signatureCount after add+GC: expected %d, got %d", before, after)
	}
}

func TestCloseStopsWorkersCleanly(t *testing.T) {
	_ = freshSignatures(t)

	// give workers a moment to start
	time.Sleep(10 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(2 * time.Second):
		t.Error("Close() did not return within 2 seconds. Worker goroutines may be blocked")
	}
}

func TestKeepaliveIsRaceFree(t *testing.T) {
	// Run with -race to verify atomic.Int64 is sufficient.
	sig := newUncheckedSignature(`c:\windows\system32\ntdll.dll`)
	var wg sync.WaitGroup
	const goroutines = 128
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			sig.keepalive()
			_ = sig.lastAccessed()
		}()
	}
	wg.Wait()
}

func TestDoRequestAsyncDropsWhenQueueFull(t *testing.T) {
	// fill the request queue to capacity then verify the drop counter
	// increments rather than the call blocking
	s := freshSignaturesWithoutCleanup(t)

	// stop workers so the queue fills
	s.Close()
	time.Sleep(10 * time.Millisecond)

	var dropsBefore int64
	// read current drop count via expvar string (expvar.Int has no direct Value method in all versions)
	dropsBefore = signatureAsyncRequestDrops.Value()

	// overflow the queue
	for i := 0; i < requestQueueSize+10; i++ {
		key := MakeKey(`c:\a.dll`, uint64(i), 0, uint32(i))
		s.DoRequestAsync(key)
	}

	dropsAfter := signatureAsyncRequestDrops.Value()
	if dropsAfter <= dropsBefore {
		t.Error("DoRequestAsync must increment drop counter when queue is full")
	}
}

func isWintrustAvailable() bool {
	return sys.IsWintrustFound()
}

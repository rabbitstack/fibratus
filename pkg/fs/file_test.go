//go:build windows
// +build windows

/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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

package fs

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func sysRoot(t *testing.T) string {
	t.Helper()
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = os.Getenv("SYSTEMROOT")
	}
	if root == "" {
		t.Skip("SystemRoot/SYSTEMROOT not set; skipping test that requires a real Windows install")
	}
	return root
}

func system32(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(sysRoot(t), "System32", name)
	if _, err := os.Stat(p); err != nil {
		t.Skipf("required system file not present: %s (%v)", p, err)
	}
	return p
}

// newTestStore builds a store without relying on the process-wide singleton
// (GetMetadataStore), so tests don't interfere with each other.
func newTestStore() *FileMetadataStore {
	return newFileMetadataStore()
}

// ---------------------------------------------------------------------
// moduleWildcards (wellKnownDLLs / wellKnownExecutables) — pure string
// matching, no disk I/O required, so these run against synthetic paths.
// ---------------------------------------------------------------------

func TestModuleWildcardsAcceptTrustedDLL(t *testing.T) {
	s := newTestStore()
	defer s.Close()

	tests := []struct {
		name string
		path string
		want bool
	}{
		{"well-known name, System32", `c:\windows\system32\kernel32.dll`, true},
		{"well-known name, SysWOW64", `c:\windows\syswow64\ntdll.dll`, true},
		{"unknown name, System32", `c:\windows\system32\totally-unknown.dll`, false},
		{"well-known name, wrong directory", `c:\temp\kernel32.dll`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := s.wellKnownDLLs.Accept(tt.path); got != tt.want {
				t.Errorf("Accept(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestModuleWildcardsAcceptTrustedExecutable(t *testing.T) {
	s := newTestStore()
	defer s.Close()

	tests := []struct {
		name string
		path string
		want bool
	}{
		{"well-known name, System32", `c:\windows\system32\svchost.exe`, true},
		{
			"well-known name but lives outside System32 (explorer.exe is under %SystemRoot%, not System32)",
			`c:\windows\explorer.exe`,
			false,
		},
		{"unknown name, System32", `c:\windows\system32\notepad.exe`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := s.wellKnownExecutables.Accept(tt.path); got != tt.want {
				t.Errorf("Accept(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestModuleWildcardsRejectsSiblingDirectorySpoof(t *testing.T) {
	s := newTestStore()
	defer s.Close()

	path := `c:\windows\system32fake\kernel32.dll`
	if s.wellKnownDLLs.Accept(path) {
		t.Error("expected sibling-directory path (system32fake) to be rejected")
	}
}

// ---------------------------------------------------------------------
// windowsUpdateWildcards
// ---------------------------------------------------------------------

func TestWindowsUpdateWildcardsAccept(t *testing.T) {
	w := windowsUpdateWildcards{
		`?:\$winreagent\scratch\*`,
		`?:\windows\winsxs\*`,
		`?:\windows\cbstemp\*`,
		`?:\windows\softwaredistribution\*`,
	}

	tests := []struct {
		path string
		want bool
	}{
		{`c:\windows\winsxs\amd64_foo\file.dll`, true},
		{`c:\windows\softwaredistribution\download\update.cab`, true},
		{`c:\windows\system32\kernel32.dll`, false},
		{`c:\users\bob\downloads\evil.exe`, false},
	}

	for _, tt := range tests {
		if got := w.Accept(tt.path); got != tt.want {
			t.Errorf("Accept(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestNormalizePath(t *testing.T) {
	s := newTestStore()
	defer s.Close()

	got := s.normalizePath(`C:\Windows\System32\KERNEL32.DLL`)
	want := `c:\windows\system32\kernel32.dll`
	if got != want {
		t.Errorf("normalizePath() = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------
// FileInfo bookkeeping
// ---------------------------------------------------------------------

func TestFileInfoKeepaliveAndLastAccessed(t *testing.T) {
	f := &FileInfo{}
	before := time.Now()
	f.keepalive()
	after := time.Now()

	got := f.lastAccessed()
	if got.Before(before.Add(-time.Second)) || got.After(after.Add(time.Second)) {
		t.Errorf("lastAccessed() = %v, expected to be between %v and %v", got, before, after)
	}
}

func TestFileMetadataStoreAddAndGet(t *testing.T) {
	s := newTestStore()
	defer s.Close()

	path := s.normalizePath(`C:\Windows\System32\kernel32.dll`)
	s.addDLL(path)

	f := s.get(path)
	if f == nil {
		t.Fatal("expected entry after addDLL, got nil")
	}
	if !f.IsDLL {
		t.Error("expected IsDLL to be true")
	}
	if !s.contains(path) {
		t.Error("expected contains() to be true")
	}
}

func TestFileMetadataStoreAddExecutable(t *testing.T) {
	s := newTestStore()
	defer s.Close()

	path := s.normalizePath(`C:\Windows\System32\svchost.exe`)
	s.addExecutable(path)

	f := s.get(path)
	if f == nil {
		t.Fatal("expected entry after addExecutable, got nil")
	}
	if !f.IsExecutable {
		t.Error("expected IsExecutable to be true")
	}
}

func TestFileMetadataStoreRemoveFile(t *testing.T) {
	s := newTestStore()
	defer s.Close()

	path := `C:\Windows\System32\kernel32.dll`
	s.addDLL(s.normalizePath(path))

	if !s.contains(s.normalizePath(path)) {
		t.Fatal("expected entry to be present before removal")
	}

	s.RemoveFile(path)

	if s.contains(s.normalizePath(path)) {
		t.Error("expected entry to be gone after RemoveFile")
	}
}

func TestFileMetadataStoreGetKeepsAlive(t *testing.T) {
	s := newTestStore()
	defer s.Close()

	path := s.normalizePath(`C:\Windows\System32\kernel32.dll`)
	s.addDLL(path)

	f := s.get(path)
	old := f.lastAccessed()

	time.Sleep(10 * time.Millisecond)
	f2 := s.get(path)
	if !f2.lastAccessed().After(old) {
		t.Error("expected lastAccessed to advance on repeated get()")
	}
}

func TestDoRequestFastPathTrustedDLL(t *testing.T) {
	s := newTestStore()
	defer s.Close()

	// Relies on the real SystemRoot literally being named "Windows"
	// (true for the overwhelming majority of installs) since the fast
	// path no longer derives the root from the environment -- see the
	// any-drive-letter/hardcoded-root design flaw noted separately.
	path := system32(t, "kernel32.dll")

	f := s.DoRequest(path)
	if f == nil {
		t.Fatal("expected non-nil FileInfo for trusted DLL fast path")
	}
	if !f.IsDLL {
		t.Error("expected IsDLL true via fast path (well-known name + trusted dir), no PE parsing needed")
	}
	if f.IsExecutable || f.IsDriver || f.IsDotnet {
		t.Errorf("fast path should only set IsDLL, got %+v", f)
	}
}

func TestDoRequestFastPathTrustedExecutable(t *testing.T) {
	s := newTestStore()
	defer s.Close()

	path := system32(t, "svchost.exe")

	f := s.DoRequest(path)
	if f == nil {
		t.Fatal("expected non-nil FileInfo for trusted executable fast path")
	}
	if !f.IsExecutable {
		t.Error("expected IsExecutable true via fast path")
	}
}

func TestDoRequestWindowsUpdateWildcardIsSkipped(t *testing.T) {
	s := newTestStore()
	defer s.Close()

	root := sysRoot(t)
	path := filepath.Join(root, "WinSxS", "some-component", "file.dll")

	f := s.DoRequest(path)
	if f != nil {
		t.Errorf("expected nil for a path matching the WinSxS wildcard, got %+v", f)
	}
	if s.contains(s.normalizePath(path)) {
		t.Error("wildcard-matched paths should never be cached")
	}
}

func TestDoRequestRealPEParsingUnlistedDLL(t *testing.T) {
	path := system32(t, "version.dll")

	s := newTestStore()
	defer s.Close()

	if _, known := s.wellKnownDLLs[strings.ToLower(filepath.Base(path))]; known {
		t.Skip("version.dll is now in wellKnownDLLs; pick another unlisted DLL to keep testing the slow path")
	}

	f := s.DoRequest(path)
	if f == nil {
		t.Fatal("expected a resolved FileInfo from real PE parsing")
	}
	if !f.IsDLL {
		t.Error("expected IsDLL true from parsed PE headers")
	}
	if f.IsExecutable {
		t.Error("did not expect IsExecutable true for a DLL")
	}
}

func TestDoRequestRealPEParsingUnlistedExecutable(t *testing.T) {
	path := system32(t, "notepad.exe")

	s := newTestStore()
	defer s.Close()

	if _, known := s.wellKnownExecutables[strings.ToLower(filepath.Base(path))]; known {
		t.Skip("notepad.exe is now in wellKnownExecutables; pick another unlisted exe to keep testing the slow path")
	}

	f := s.DoRequest(path)
	if f == nil {
		t.Fatal("expected a resolved FileInfo from real PE parsing")
	}
	if !f.IsExecutable {
		t.Error("expected IsExecutable true from parsed PE headers")
	}
	if f.IsDLL {
		t.Error("did not expect IsDLL true for a plain executable")
	}
}

func TestDoRequestRealPEParsingDotnetAssembly(t *testing.T) {
	root := sysRoot(t)

	matches, err := filepath.Glob(filepath.Join(root, "Microsoft.NET", "Framework64", "*", "System.IO.dll"))
	if err != nil || len(matches) == 0 {
		t.Skip("no .NET Framework csc.exe found on this machine")
	}

	var path string
	for _, c := range matches {
		if _, err := os.Stat(c); err == nil {
			path = c
			break
		}
	}
	if path == "" {
		t.Skip("no .NET Framework csc.exe found on this machine")
	}

	s := newTestStore()
	defer s.Close()

	f := s.DoRequest(path)
	if f == nil {
		t.Fatal("expected a resolved FileInfo")
	}
	if !f.IsDotnet {
		t.Error("expected IsDotnet true for a managed .NET executable")
	}
}

func TestDoRequestNonexistentFileReturnsNil(t *testing.T) {
	s := newTestStore()
	defer s.Close()

	path := filepath.Join(sysRoot(t), "System32", "this-file-does-not-exist-12345.dll")

	f := s.DoRequest(path)
	if f != nil {
		t.Errorf("expected nil FileInfo for a nonexistent file, got %+v", f)
	}
	if s.contains(s.normalizePath(path)) {
		t.Error("a failed parse should not populate the cache")
	}
}

func TestDoRequestAsyncPopulatesCacheEventually(t *testing.T) {
	path := system32(t, "version.dll")

	s := newTestStore()
	defer s.Close()

	s.DoRequestAsync(path)

	deadline := time.Now().Add(2 * time.Second)
	var f *FileInfo
	for time.Now().Before(deadline) {
		if f = s.get(s.normalizePath(path)); f != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if f == nil {
		t.Fatal("expected DoRequestAsync to eventually populate the cache")
	}
	if !f.IsDLL {
		t.Error("expected IsDLL true")
	}
}

func TestDoRequestAsyncIsNoopWhenAlreadyCached(t *testing.T) {
	s := newTestStore()
	defer s.Close()

	path := s.normalizePath(`C:\Windows\System32\kernel32.dll`)
	s.addDLL(path)
	original := s.get(path)

	s.DoRequestAsync(`C:\Windows\System32\kernel32.dll`)
	time.Sleep(50 * time.Millisecond)

	if got := s.get(path); got != original {
		t.Error("expected DoRequestAsync to leave an already-cached entry untouched")
	}
}

func TestDoRequestConcurrentSameFileSingleflight(t *testing.T) {
	path := system32(t, "version.dll")

	s := newTestStore()
	defer s.Close()

	const n = 32
	var wg sync.WaitGroup
	results := make([]*FileInfo, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = s.DoRequest(path)
		}(i)
	}
	wg.Wait()

	for i, f := range results {
		if f == nil {
			t.Fatalf("goroutine %d got nil FileInfo", i)
		}
		if !f.IsDLL {
			t.Errorf("goroutine %d: expected IsDLL true", i)
		}
	}
	if final := s.get(s.normalizePath(path)); final == nil {
		t.Fatal("expected a cached entry after concurrent resolution")
	}
}

func TestDoRequestConcurrentDifferentFilesNoRace(t *testing.T) {
	root := sysRoot(t)
	names := []string{"version.dll", "notepad.exe", "kernel32.dll", "svchost.exe"}

	var paths []string
	for _, n := range names {
		p := filepath.Join(root, "System32", n)
		if _, err := os.Stat(p); err == nil {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		t.Skip("none of the candidate files are present")
	}

	s := newTestStore()
	defer s.Close()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		for _, p := range paths {
			wg.Add(1)
			go func(p string) {
				defer wg.Done()
				_ = s.DoRequest(p)
			}(p)
		}
	}
	wg.Wait()
}

// ---------------------------------------------------------------------
// GC / TTL eviction
// ---------------------------------------------------------------------

func TestGCEvictsStaleEntries(t *testing.T) {
	s := newTestStore()
	defer s.Close()

	path := s.normalizePath(`C:\Windows\System32\kernel32.dll`)
	s.addDLL(path)

	f := s.get(path)
	f.accessed.Store(time.Now().Add(-metadataTTL - time.Minute).UnixNano())

	s.gc()

	if s.contains(path) {
		t.Error("expected stale entry to be evicted by gc()")
	}
}

func TestGCKeepsFreshEntries(t *testing.T) {
	s := newTestStore()
	defer s.Close()

	path := s.normalizePath(`C:\Windows\System32\kernel32.dll`)
	s.addDLL(path)
	s.get(path) // refresh accessed timestamp

	s.gc()

	if !s.contains(path) {
		t.Error("expected freshly-accessed entry to survive gc()")
	}
}

func TestGCRacesWithConcurrentAccess(t *testing.T) {
	s := newTestStore()
	defer s.Close()

	path := s.normalizePath(`C:\Windows\System32\kernel32.dll`)
	s.addDLL(path)

	var stop atomic.Bool
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			s.get(path)
		}
	}()

	for i := 0; i < 50; i++ {
		s.gc()
	}
	stop.Store(true)
	wg.Wait()
}

func TestCloseStopsWorkersAndPurger(t *testing.T) {
	s := newTestStore()
	s.Close()

	path := s.normalizePath(`C:\Windows\System32\kernel32.dll`)
	s.addDLL(path)
	if !s.contains(path) {
		t.Error("fast-path cache writes should still work after Close()")
	}
}

func TestGetFileType(t *testing.T) {
	var tests = []struct {
		filename string
		opts     uint32
		wants    FileType
	}{
		{
			`_fixtures`,
			16777249,
			Directory,
		},
		{
			`_fixtures`,
			25165857,
			Directory,
		},
		{
			`C:\Users\bunny\AppData\Local\Mozilla\Firefox\Profiles\profile1.tmp`,
			18874368,
			Regular,
		},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			assert.Equal(t, tt.wants, GetFileType(tt.filename, tt.opts))
		})
	}
}

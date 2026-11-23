//go:build windows || linux

/*
 * Copyright 2026 by Nedim Sabic Sabic
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

package fswatcher

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"
)

const wait = 2 * time.Second

func newTestWatcher(t *testing.T, dirs ...string) *Watcher {
	t.Helper()
	w, err := NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	for _, dir := range dirs {
		if err := w.Add(dir); err != nil {
			t.Fatal(err)
		}
	}
	return w
}

// expect consumes events until one matches the name and operation.
func expect(t *testing.T, w *Watcher, name string, op Op) {
	t.Helper()
	timeout := time.After(wait)
	for {
		select {
		case ev, ok := <-w.Events:
			if !ok {
				t.Fatalf("events channel closed while waiting for %s on %q", op, name)
			}
			if ev.Name == name && ev.Has(op) {
				return
			}
		case err := <-w.Errors:
			t.Fatalf("unexpected error while waiting for %s on %q: %v", op, name, err)
		case <-timeout:
			t.Fatalf("timed out waiting for %s on %q", op, name)
		}
	}
}

// expectNone fails if any event shows up within d.
func expectNone(t *testing.T, w *Watcher, d time.Duration) {
	t.Helper()
	select {
	case ev := <-w.Events:
		t.Fatalf("unexpected event: %s", ev)
	case err := <-w.Errors:
		t.Fatalf("unexpected error: %v", err)
	case <-time.After(d):
	}
}

// drain discards the events that are still on their way.
func drain(w *Watcher) {
	timeout := time.After(300 * time.Millisecond)
	for {
		select {
		case <-w.Events:
		case <-timeout:
			return
		}
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCreateWriteRemove(t *testing.T) {
	dir := t.TempDir()
	w := newTestWatcher(t, dir)
	f := filepath.Join(dir, "rule.yml")

	write(t, f, "a: 1")
	expect(t, w, f, Create)
	expect(t, w, f, Write)
	drain(w)

	write(t, f, "a: 2")
	expect(t, w, f, Write)
	drain(w)

	if err := os.Remove(f); err != nil {
		t.Fatal(err)
	}
	expect(t, w, f, Remove)
}

func TestRename(t *testing.T) {
	dir := t.TempDir()
	w := newTestWatcher(t, dir)
	src, dst := filepath.Join(dir, "old.yml"), filepath.Join(dir, "new.yml")

	write(t, src, "x")
	drain(w)

	if err := os.Rename(src, dst); err != nil {
		t.Fatal(err)
	}
	expect(t, w, src, Rename)
	expect(t, w, dst, Create)
}

func TestChmod(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("attribute changes are reported as writes on Windows")
	}
	dir := t.TempDir()
	w := newTestWatcher(t, dir)
	f := filepath.Join(dir, "a.yml")
	write(t, f, "x")
	drain(w)

	if err := os.Chmod(f, 0o600); err != nil {
		t.Fatal(err)
	}
	expect(t, w, f, Chmod)
}

func TestMultipleDirs(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	w := newTestWatcher(t, a, b)

	fa, fb := filepath.Join(a, "r.yml"), filepath.Join(b, "r.yml")
	write(t, fa, "x")
	expect(t, w, fa, Create)
	write(t, fb, "x")
	expect(t, w, fb, Create)
}

func TestSubdirectoriesAreNotWatched(t *testing.T) {
	dir := t.TempDir()
	w := newTestWatcher(t, dir)

	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	expect(t, w, sub, Create)
	drain(w)

	write(t, filepath.Join(sub, "nested.yml"), "x")
	expectNone(t, w, 300*time.Millisecond)
}

func TestAddIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	w := newTestWatcher(t, dir)
	if err := w.Add(dir); err != nil {
		t.Fatal(err)
	}
	if got := w.WatchList(); len(got) != 1 {
		t.Fatalf("expected 1 watch, got %v", got)
	}
	write(t, filepath.Join(dir, "r.yml"), "x")
	expect(t, w, filepath.Join(dir, "r.yml"), Create)
}

func TestAddErrors(t *testing.T) {
	dir := t.TempDir()
	w := newTestWatcher(t)

	if err := w.Add(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected not exist error, got %v", err)
	}
	f := filepath.Join(dir, "file.txt")
	write(t, f, "x")
	if err := w.Add(f); err == nil {
		t.Fatal("expected an error when watching a regular file")
	}
	if got := w.WatchList(); len(got) != 0 {
		t.Fatalf("failed adds must not leave watches behind, got %v", got)
	}
}

func TestRemoveWatch(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	w := newTestWatcher(t, a, b)

	if err := w.Remove(a); err != nil {
		t.Fatal(err)
	}
	if err := w.Remove(a); !errors.Is(err, ErrNonExistentWatch) {
		t.Fatalf("expected ErrNonExistentWatch, got %v", err)
	}

	write(t, filepath.Join(a, "r.yml"), "x")
	expectNone(t, w, 300*time.Millisecond)

	// the other directory is still watched
	fb := filepath.Join(b, "r.yml")
	write(t, fb, "x")
	expect(t, w, fb, Create)
}

func TestWatchList(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	w := newTestWatcher(t, a, b)

	got := w.WatchList()
	want := []string{a, b}
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("watch list: got %v, want %v", got, want)
	}
}

func TestWatchedDirectoryRemoved(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("removal of the watched directory is only reported on Linux")
	}
	sub := filepath.Join(t.TempDir(), "watched")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	w := newTestWatcher(t, sub)

	if err := os.Remove(sub); err != nil {
		t.Fatal(err)
	}
	expect(t, w, sub, Remove)
}

func TestBufferedWatcher(t *testing.T) {
	dir := t.TempDir()
	w, err := NewBufferedWatcher(64)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := w.Add(dir); err != nil {
		t.Fatal(err)
	}

	// nobody reads while the files are being created
	for _, n := range []string{"a.yml", "b.yml", "c.yml"} {
		write(t, filepath.Join(dir, n), "x")
	}
	for _, n := range []string{"a.yml", "b.yml", "c.yml"} {
		expect(t, w, filepath.Join(dir, n), Create)
	}
}

func TestClose(t *testing.T) {
	dir := t.TempDir()
	w := newTestWatcher(t, dir)

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case _, ok := <-w.Events:
		if ok {
			t.Fatal("expected Events to be closed")
		}
	case <-time.After(wait):
		t.Fatal("Events was not closed")
	}
	select {
	case _, ok := <-w.Errors:
		if ok {
			t.Fatal("expected Errors to be closed")
		}
	case <-time.After(wait):
		t.Fatal("Errors was not closed")
	}

	if err := w.Add(dir); !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed from Add, got %v", err)
	}
	if err := w.Remove(dir); !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed from Remove, got %v", err)
	}
}

// Close must not hang when the consumer stopped reading
// and the reader goroutine is stuck delivering an event.
func TestCloseWithUnreadEvents(t *testing.T) {
	dir := t.TempDir()
	w := newTestWatcher(t, dir)
	for _, n := range []string{"a.yml", "b.yml", "c.yml"} {
		write(t, filepath.Join(dir, n), "x")
	}
	time.Sleep(100 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		_ = w.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(wait):
		t.Fatal("Close blocked on undelivered events")
	}
}

func TestEventString(t *testing.T) {
	ev := Event{Name: "a.yml", Op: Create | Write}
	if got, want := ev.String(), `"a.yml": CREATE|WRITE`; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	if !ev.Has(Create) || !ev.Has(Write) || ev.Has(Remove) {
		t.Fatal("unexpected Has results")
	}
	if got := Op(0).String(); got != "[no events]" {
		t.Fatalf("got %s", got)
	}
}

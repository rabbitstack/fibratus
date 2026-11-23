//go:build windows

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
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const (
	fileListDirectory = 0x1 // FILE_LIST_DIRECTORY

	notifyFilter = syscall.FILE_NOTIFY_CHANGE_FILE_NAME |
		syscall.FILE_NOTIFY_CHANGE_DIR_NAME |
		syscall.FILE_NOTIFY_CHANGE_SIZE |
		syscall.FILE_NOTIFY_CHANGE_LAST_WRITE |
		syscall.FILE_NOTIFY_CHANGE_CREATION
)

// fileNotifyInformation mirrors the FILE_NOTIFY_INFORMATION structure.
type fileNotifyInformation struct {
	NextEntryOffset uint32
	Action          uint32
	FileNameLength  uint32
	FileName        uint16
}

// dirWatch is a single watched directory. Its goroutine blocks in a
// synchronous ReadDirectoryChangesW call until something changes or
// the read is canceled.
type dirWatch struct {
	dir     string
	handle  syscall.Handle
	stopped atomic.Bool
	done    chan struct{} // closed when the reader goroutine exits

	mu     sync.Mutex // guards handle against use-after-close
	closed bool
}

func (dw *dirWatch) cancel() {
	dw.mu.Lock()
	defer dw.mu.Unlock()
	if !dw.closed {
		_ = syscall.CancelIoEx(dw.handle, nil)
	}
}

func (dw *dirWatch) closeHandle() {
	dw.mu.Lock()
	defer dw.mu.Unlock()
	if !dw.closed {
		dw.closed = true
		_ = syscall.CloseHandle(dw.handle)
	}
}

// stop cancels the pending read and waits for the reader goroutine to exit.
func (dw *dirWatch) stop() {
	dw.stopped.Store(true)
	// a read issued between the stopped check and the cancel would never be
	// canceled, so keep cancelling until the reader has exited
	for {
		select {
		case <-dw.done:
			return
		default:
		}
		dw.cancel()
		select {
		case <-dw.done:
			return
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// Watcher watches directories for changes and delivers the notifications
// on the Events channel. Failures are delivered on the Errors channel.
// Both channels are closed when the watcher is closed.
//
// A Watcher must be created with NewWatcher or NewBufferedWatcher.
type Watcher struct {
	// Events is the channel of file system events.
	Events chan Event
	// Errors is the channel of asynchronous errors.
	Errors chan error

	mu      sync.Mutex
	watches map[string]*dirWatch
	closed  bool

	wg   sync.WaitGroup
	done chan struct{} // closed by Close to unblock senders
}

// NewWatcher creates a watcher whose Events channel is unbuffered.
func NewWatcher() (*Watcher, error) {
	return NewBufferedWatcher(0)
}

// NewBufferedWatcher creates a watcher whose Events channel has room for
// sz events. A buffer absorbs bursts so the OS is drained even if the
// consumer is briefly slow.
func NewBufferedWatcher(sz uint) (*Watcher, error) {
	return &Watcher{
		Events:  make(chan Event, sz),
		Errors:  make(chan error),
		watches: make(map[string]*dirWatch),
		done:    make(chan struct{}),
	}, nil
}

// Add starts watching the named directory. It is not an error to add a
// directory that is already watched. Subdirectories are not watched.
func (w *Watcher) Add(name string) error {
	name = filepath.Clean(name)

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrClosed
	}
	if _, ok := w.watches[name]; ok {
		return nil
	}
	fi, err := os.Stat(name)
	if err != nil {
		return fmt.Errorf("fswatcher: unable to watch directory %s: %w", name, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("fswatcher: unable to watch %s: not a directory", name)
	}
	p, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("fswatcher: unable to watch directory %s: %w", name, err)
	}
	h, err := syscall.CreateFile(
		p,
		fileListDirectory,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return fmt.Errorf("fswatcher: unable to open directory %s: %w", name, err)
	}
	dw := &dirWatch{dir: name, handle: h, done: make(chan struct{})}
	w.watches[name] = dw
	w.wg.Add(1)
	go w.read(dw)
	return nil
}

// Remove stops watching the named directory.
func (w *Watcher) Remove(name string) error {
	name = filepath.Clean(name)

	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return ErrClosed
	}
	dw, ok := w.watches[name]
	if !ok {
		w.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrNonExistentWatch, name)
	}
	delete(w.watches, name)
	w.mu.Unlock()

	dw.stop()
	return nil
}

// WatchList returns the directories currently being watched.
func (w *Watcher) WatchList() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	list := make([]string, 0, len(w.watches))
	for name := range w.watches {
		list = append(list, name)
	}
	return list
}

// Close stops the watcher, releases the OS resources, and closes the
// Events and Errors channels. It is safe to call Close more than once.
func (w *Watcher) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	close(w.done)
	watches := w.watches
	w.watches = make(map[string]*dirWatch)
	w.mu.Unlock()

	for _, dw := range watches {
		dw.stop()
	}
	// readers that already dropped themselves after a failure
	// are not in the map, so wait for every goroutine
	w.wg.Wait()
	close(w.Events)
	close(w.Errors)
	return nil
}

func (w *Watcher) sendEvent(e Event) bool {
	select {
	case w.Events <- e:
		return true
	case <-w.done:
		return false
	}
}

func (w *Watcher) sendError(err error) bool {
	select {
	case w.Errors <- err:
		return true
	case <-w.done:
		return false
	}
}

func (w *Watcher) read(dw *dirWatch) {
	defer w.wg.Done()
	defer close(dw.done)
	defer dw.closeHandle()

	buf := make([]byte, 64*1024)
	for !dw.stopped.Load() {
		var n uint32
		err := syscall.ReadDirectoryChanges(dw.handle, &buf[0], uint32(len(buf)), false, notifyFilter, &n, nil, 0)
		if err != nil {
			if dw.stopped.Load() || err == syscall.ERROR_OPERATION_ABORTED {
				return
			}
			w.sendError(fmt.Errorf("fswatcher: directory change notification for %s failed: %w", dw.dir, err))
			// the watch is dead, so stop tracking it
			w.mu.Lock()
			if w.watches[dw.dir] == dw {
				delete(w.watches, dw.dir)
			}
			w.mu.Unlock()
			return
		}
		// a zero-length result means the notification buffer overflowed,
		// so some changes were lost
		if n == 0 {
			if !w.sendError(ErrEventOverflow) {
				return
			}
			continue
		}
		if !w.dispatch(dw.dir, buf[:n]) {
			return
		}
	}
}

// dispatch decodes the FILE_NOTIFY_INFORMATION records in the buffer.
// It returns false when the watcher was closed while delivering.
func (w *Watcher) dispatch(dir string, buf []byte) bool {
	hdr := int(unsafe.Offsetof(fileNotifyInformation{}.FileName))
	var off uint32
	for int(off)+hdr <= len(buf) {
		info := (*fileNotifyInformation)(unsafe.Pointer(&buf[off]))
		if int(off)+hdr+int(info.FileNameLength) > len(buf) {
			return true
		}
		var name string
		if n := info.FileNameLength / 2; n > 0 {
			name = syscall.UTF16ToString(unsafe.Slice(&info.FileName, n))
		}

		var op Op
		switch info.Action {
		case syscall.FILE_ACTION_ADDED, syscall.FILE_ACTION_RENAMED_NEW_NAME:
			op = Create
		case syscall.FILE_ACTION_REMOVED:
			op = Remove
		case syscall.FILE_ACTION_MODIFIED:
			op = Write
		case syscall.FILE_ACTION_RENAMED_OLD_NAME:
			op = Rename
		}
		if op != 0 {
			if !w.sendEvent(Event{Name: filepath.Join(dir, name), Op: op}) {
				return false
			}
		}
		if info.NextEntryOffset == 0 {
			return true
		}
		off += info.NextEntryOffset
	}
	return true
}

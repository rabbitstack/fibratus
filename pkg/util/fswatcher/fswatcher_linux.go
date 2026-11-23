//go:build linux

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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

const watchMask = syscall.IN_CREATE |
	syscall.IN_MOVED_TO |
	syscall.IN_MOVED_FROM |
	syscall.IN_DELETE |
	syscall.IN_DELETE_SELF |
	syscall.IN_MOVE_SELF |
	syscall.IN_MODIFY |
	syscall.IN_ATTRIB |
	syscall.IN_ONLYDIR

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
	fd      int      // inotify descriptor, owned by file
	file    *os.File // makes blocking reads interruptible via the runtime poller
	paths   map[int]string
	watches map[string]int
	closed  bool

	done       chan struct{} // closed by Close to unblock senders
	readerDone chan struct{} // closed when the reader goroutine exits
}

// NewWatcher creates a watcher whose Events channel is unbuffered.
func NewWatcher() (*Watcher, error) {
	return NewBufferedWatcher(0)
}

// NewBufferedWatcher creates a watcher whose Events channel has room for
// sz events. A buffer absorbs bursts so the OS queue is drained even if
// the consumer is briefly slow.
func NewBufferedWatcher(sz uint) (*Watcher, error) {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("fswatcher: unable to initialize inotify: %w", err)
	}
	// the descriptor is non-blocking, so os.File registers it with the
	// runtime poller and Close unblocks a pending Read
	file := os.NewFile(uintptr(fd), "inotify")
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("fswatcher: unable to wrap inotify descriptor")
	}
	w := &Watcher{
		Events:     make(chan Event, sz),
		Errors:     make(chan error),
		fd:         fd,
		file:       file,
		paths:      make(map[int]string),
		watches:    make(map[string]int),
		done:       make(chan struct{}),
		readerDone: make(chan struct{}),
	}
	go w.readEvents()
	return w, nil
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
	wd, err := syscall.InotifyAddWatch(w.fd, name, watchMask)
	if err != nil {
		return fmt.Errorf("fswatcher: unable to watch directory %s: %w", name, err)
	}
	// the kernel hands out the same descriptor when the same
	// directory is reached through a different path
	if old, ok := w.paths[wd]; ok && old != name {
		delete(w.watches, old)
	}
	w.paths[wd] = name
	w.watches[name] = wd
	return nil
}

// Remove stops watching the named directory.
func (w *Watcher) Remove(name string) error {
	name = filepath.Clean(name)

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrClosed
	}
	wd, ok := w.watches[name]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNonExistentWatch, name)
	}
	delete(w.watches, name)
	delete(w.paths, wd)
	// EINVAL means the kernel already dropped the watch (the directory is gone)
	if _, err := syscall.InotifyRmWatch(w.fd, uint32(wd)); err != nil && err != syscall.EINVAL {
		return fmt.Errorf("fswatcher: unable to remove watch %s: %w", name, err)
	}
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
	w.mu.Unlock()

	// closing the file wakes up the reader blocked in Read
	err := w.file.Close()
	<-w.readerDone
	return err
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

func (w *Watcher) readEvents() {
	defer close(w.readerDone)
	defer close(w.Errors)
	defer close(w.Events)

	buf := make([]byte, 64*1024)
	for {
		n, err := w.file.Read(buf)
		if err != nil {
			if errors.Is(err, os.ErrClosed) || errors.Is(err, io.EOF) {
				return
			}
			w.sendError(fmt.Errorf("fswatcher: unable to read inotify events: %w", err))
			return
		}
		if !w.handle(buf[:n]) {
			return
		}
	}
}

// handle decodes the batch of inotify events:
//
//	struct inotify_event { int32 wd; uint32 mask, cookie, len; char name[]; }
//
// It returns false when the watcher was closed while delivering.
func (w *Watcher) handle(buf []byte) bool {
	for off := 0; off+syscall.SizeofInotifyEvent <= len(buf); {
		wd := int(int32(binary.NativeEndian.Uint32(buf[off:])))
		mask := binary.NativeEndian.Uint32(buf[off+4:])
		size := int(binary.NativeEndian.Uint32(buf[off+12:]))
		start := off + syscall.SizeofInotifyEvent
		end := start + size
		if end > len(buf) {
			return true
		}
		off = end

		if mask&syscall.IN_Q_OVERFLOW != 0 {
			if !w.sendError(ErrEventOverflow) {
				return false
			}
			continue
		}

		w.mu.Lock()
		dir, ok := w.paths[wd]
		switch {
		case mask&(syscall.IN_IGNORED|syscall.IN_UNMOUNT) != 0:
			// the kernel dropped the watch
			delete(w.paths, wd)
			delete(w.watches, dir)
		case mask&syscall.IN_MOVE_SELF != 0 && ok:
			// the watched directory was moved, so
			// the path we know it by is no longer valid
			delete(w.paths, wd)
			delete(w.watches, dir)
			if !w.closed {
				_, _ = syscall.InotifyRmWatch(w.fd, uint32(wd))
			}
		}
		w.mu.Unlock()

		// either a watch we dropped ourselves (Remove) or bookkeeping only
		op := opFromMask(mask)
		if !ok || op == 0 || mask&(syscall.IN_IGNORED|syscall.IN_UNMOUNT) != 0 {
			continue
		}

		// names are NUL-padded to an alignment boundary
		path := dir
		if name := bytes.TrimRight(buf[start:end], "\x00"); len(name) > 0 {
			path = filepath.Join(dir, string(name))
		}
		if !w.sendEvent(Event{Name: path, Op: op}) {
			return false
		}
	}
	return true
}

func opFromMask(mask uint32) (op Op) {
	if mask&(syscall.IN_CREATE|syscall.IN_MOVED_TO) != 0 {
		op |= Create
	}
	if mask&syscall.IN_MODIFY != 0 {
		op |= Write
	}
	if mask&(syscall.IN_DELETE|syscall.IN_DELETE_SELF) != 0 {
		op |= Remove
	}
	if mask&(syscall.IN_MOVED_FROM|syscall.IN_MOVE_SELF) != 0 {
		op |= Rename
	}
	if mask&syscall.IN_ATTRIB != 0 {
		op |= Chmod
	}
	return op
}

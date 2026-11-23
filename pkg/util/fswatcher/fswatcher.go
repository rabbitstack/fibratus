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

// Package fswatcher provides a small cross-platform directory watcher
// whose API follows github.com/fsnotify/fsnotify. On Windows it is backed
// by ReadDirectoryChangesW and on Linux by inotify.
//
// A [Watcher] delivers [Event] values on its Events channel and
// asynchronous failures on its Errors channel. Both channels are closed
// when the watcher is closed:
//
// Only directories can be watched, and watching is not recursive: events
// are reported for the direct children of every directory passed to Add.
// Event names are the watched directory joined with the entry name.
//
// The watcher reports raw OS notifications. A single logical change
// (e.g. an editor saving a file) can produce several events, so consumers
// that react by re-reading state should debounce.
package fswatcher

import (
	"errors"
	"fmt"
	"strings"
)

// Event represents a single file system notification.
type Event struct {
	// Name is the path of the entry that changed, built by joining the
	// watched directory with the entry name. For events about the watched
	// directory itself (it was removed or renamed) it is the watched path.
	Name string

	// Op is the set of operations that occurred.
	Op Op
}

// Op describes a set of file operations.
type Op uint32

// The operations a watcher can report. Not every operation is reported on
// every platform.
const (
	// Create is reported when a file or directory is created in, or
	// moved into, a watched directory.
	Create Op = 1 << iota

	// Write is reported when a file is modified.
	Write

	// Remove is reported when a file or directory is deleted from a watched
	// directory, or when the watched directory itself is deleted.
	Remove

	// Rename is reported for the old name when a file or directory is
	// renamed or moved out of a watched directory. The new name, when it is
	// inside a watched directory, is reported as Create.
	Rename

	// Chmod is reported when file attributes change. It is only reported
	// on Linux; Windows folds attribute changes into Write.
	Chmod
)

// Has reports whether the operation set contains h.
func (o Op) Has(h Op) bool { return o&h != 0 }

// Has reports whether the event's operation set contains op.
func (e Event) Has(op Op) bool { return e.Op.Has(op) }

// String returns the operations separated by "|", e.g. "CREATE|WRITE".
func (o Op) String() string {
	var b strings.Builder
	add := func(op Op, s string) {
		if o&op == 0 {
			return
		}
		if b.Len() > 0 {
			b.WriteByte('|')
		}
		b.WriteString(s)
	}
	add(Create, "CREATE")
	add(Write, "WRITE")
	add(Remove, "REMOVE")
	add(Rename, "RENAME")
	add(Chmod, "CHMOD")
	if b.Len() == 0 {
		return "[no events]"
	}
	return b.String()
}

// String returns a human-readable form of the event, e.g. `"/tmp/a.yml": WRITE`.
func (e Event) String() string {
	return fmt.Sprintf("%q: %s", e.Name, e.Op.String())
}

var (
	// ErrClosed is returned by Add and Remove after the watcher is closed.
	ErrClosed = errors.New("fswatcher: watcher already closed")

	// ErrEventOverflow is sent on the Errors channel when the OS dropped
	// notifications because its event queue overflowed. Some changes were
	// missed, so consumers should re-scan the watched directories.
	ErrEventOverflow = errors.New("fswatcher: queue or buffer overflow")

	// ErrNonExistentWatch is returned by Remove for a path that isn't being watched.
	ErrNonExistentWatch = errors.New("fswatcher: can't remove non-existent watch")

	// ErrUnsupported is returned on platforms without a watcher implementation.
	ErrUnsupported = errors.New("fswatcher: unsupported platform")
)

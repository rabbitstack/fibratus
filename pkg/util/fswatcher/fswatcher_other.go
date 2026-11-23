//go:build !windows && !linux

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

// Watcher is a placeholder so code importing the package compiles on
// platforms without an implementation. Every constructor fails with
// ErrUnsupported.
type Watcher struct {
	Events chan Event
	Errors chan error
}

// NewWatcher always returns ErrUnsupported on this platform.
func NewWatcher() (*Watcher, error) { return nil, ErrUnsupported }

// NewBufferedWatcher always returns ErrUnsupported on this platform.
func NewBufferedWatcher(uint) (*Watcher, error) { return nil, ErrUnsupported }

// Add always returns ErrUnsupported on this platform.
func (*Watcher) Add(string) error { return ErrUnsupported }

// Remove always returns ErrUnsupported on this platform.
func (*Watcher) Remove(string) error { return ErrUnsupported }

// WatchList always returns nil on this platform.
func (*Watcher) WatchList() []string { return nil }

// Close is a no-op on this platform.
func (*Watcher) Close() error { return nil }

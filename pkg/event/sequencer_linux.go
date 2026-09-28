//go:build linux

/*
 * Copyright 2026 by Mostafa Moradian
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

package event

import "sync/atomic"

// Sequencer increments the event sequence number.
type Sequencer struct {
	seq uint64
}

// NewSequencer creates an in-memory event sequencer.
func NewSequencer() *Sequencer {
	return &Sequencer{}
}

// Increment increments the sequence number atomically.
func (s *Sequencer) Increment() {
	atomic.AddUint64(&s.seq, 1)
}

// Get returns the current sequence number.
func (s *Sequencer) Get() uint64 {
	return atomic.LoadUint64(&s.seq)
}

// Reset sets the sequence number to zero.
func (s *Sequencer) Reset() error {
	atomic.StoreUint64(&s.seq, 0)
	return nil
}

// Close is a no-op on Linux.
func (s *Sequencer) Close() error { return nil }

// Shutdown closes the sequencer.
func (s *Sequencer) Shutdown() error { return s.Close() }

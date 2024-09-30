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

package kevent

import (
	"errors"
	"expvar"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	"golang.org/x/sys/windows/registry"
	"os"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// seqVName is the name of the registry value that stores the QWORD sequence.
	seqVName   = "EventSequence"
	invalidKey = registry.Key(syscall.InvalidHandle)
)

var seqStoreErrors = expvar.NewInt("kevent.seq.store.errors")
var seqInitErrors = expvar.NewMap("kevent.seq.init.errors")
var errInvalidVolatileKey = errors.New("couldn't open HKCU/Volatile Environment key")

// Sequencer is responsible for incrementing, getting and persisting the kevent sequence number in the Windows registry.
type Sequencer struct {
	key  registry.Key
	quit chan struct{}
	seq  uint64
}

// NewSequencer creates a fresh kevent sequencer. If the `KeventSeq` value is present under the volatile key, the current
// sequence number is initialized to the last stored sequence. The sequencer schedules a ticker that periodically dumps
// the current sequence number into the registry value.
func NewSequencer() *Sequencer {
	access := uint32(registry.QUERY_VALUE | registry.SET_VALUE)
	key, err := registry.OpenKey(registry.CURRENT_USER, "Volatile Environment", access)
	if err != nil {
		seqInitErrors.Add(err.Error(), 1)
		return &Sequencer{key: invalidKey, quit: make(chan struct{}, 1)}
	}
	s := &Sequencer{
		key:  key,
		quit: make(chan struct{}, 1),
		seq:  uint64(0),
	}
	s.seq, _, _ = key.GetIntegerValue(seqVName)

	go s.store()

	return s
}

// Store saves the current sequence value in the registry.
func (s *Sequencer) Store() error {
	if s.key == invalidKey {
		// try to open the key again
		var err error
		access := uint32(registry.QUERY_VALUE | registry.SET_VALUE)
		s.key, err = registry.OpenKey(registry.CURRENT_USER, "Volatile Environment", access)
		if err != nil {
			return errInvalidVolatileKey
		}
	}
	nextSeq := s.Get()
	prevSeq, _, err := s.key.GetIntegerValue(seqVName)
	if err == nil && nextSeq < prevSeq {
		return fmt.Errorf("current sequence number %d is lower than registry value %d", nextSeq, prevSeq)
	}
	return s.key.SetQWordValue(seqVName, nextSeq)
}

// Increment increments the sequence number atomically.
func (s *Sequencer) Increment() {
	atomic.AddUint64(&s.seq, 1)
}

// Get returns the current sequence number.
func (s *Sequencer) Get() uint64 {
	return atomic.LoadUint64(&s.seq)
}

// Reset removes the sequence value from the registry and sets the sequence number to zero.
func (s *Sequencer) Reset() error {
	atomic.StoreUint64(&s.seq, 0)
	if s.key == invalidKey {
		return errInvalidVolatileKey
	}
	err := s.key.DeleteValue(seqVName)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// Close shutdowns the event sequencer.
func (s *Sequencer) Close() error {
	s.quit <- struct{}{}
	return s.key.Close()
}

// Shutdown stores the sequence and closes the event sequencer.
func (s *Sequencer) Shutdown() error {
	return multierror.Wrap(s.Store(), s.Close())
}

// store periodically dumps the sequence number into registry value.
func (s *Sequencer) store() {
	ticker := time.NewTicker(time.Second * 5)
	for {
		select {
		case <-ticker.C:
			if err := s.Store(); err != nil {
				seqStoreErrors.Add(1)
			}
		case <-s.quit:
			ticker.Stop()
			return
		}
	}
}

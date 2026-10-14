/*
 * Copyright 2019-2026 by Nedim Sabic Sabic
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

package pipeline

import (
	"errors"
	"sync/atomic"
)

// cacheLine is deliberately 128: modern x86 prefetches adjacent line pairs and
// Apple/ARM cores use 128-byte lines, so 64 isn't enough to stop false sharing.
const cacheLine = 128

// ErrRingNoSlots indicates that the ring has run out of free slots.
var ErrRingNoSlots = errors.New("ring: out of free slots")

// Ring is a bounded lock-free single-producer/single-consumer ring.
//
// Exactly one goroutine may call the producer methods (Slot, Publish, Offer)
// and exactly one goroutine may call the consumer methods (Claim, Release,
// Drain) at any given time. Len and Cap are safe from anywhere.
//
// Each side keeps a private copy of its own index and a cached copy of the
// other side's index, so the shared cache lines are touched only when the
// ring looks full (producer) or empty (consumer), and the consumer publishes
// its progress once per batch rather than once per element.
//
// T may be a large struct (zero-copy value slots: Slot/Publish and
// Claim/Release) or a pointer or small value (Offer/Drain).
type Ring[T any] struct {
	_ [cacheLine]byte

	// producer-owned
	tail      atomic.Uint64 // published count, read by the consumer
	ptail     uint64        // private copy of tail
	headCache uint64        // last observed head
	_         [cacheLine - 24]byte

	// consumer-owned
	head      atomic.Uint64 // released count, read by the producer
	chead     uint64        // private copy of head
	tailCache uint64        // last observed tail
	_         [cacheLine - 24]byte

	// read-only after construction
	size uint64
	mask uint64
	buf  []T
}

// NewRing creates a ring whose capacity is size rounded up to a power of two.
func NewRing[T any](size int) *Ring[T] {
	n := nextPow2(size)
	return &Ring[T]{size: uint64(n), mask: uint64(n - 1), buf: make([]T, n)}
}

func nextPow2(n int) int {
	if n < 2 {
		return 2
	}
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

// Cap returns the number of slots.
func (r *Ring[T]) Cap() int { return int(r.size) }

// Len returns the approximate number of published, unreleased slots.
func (r *Ring[T]) Len() int {
	h := r.head.Load() // head first: tail only grows, so tail >= h always holds
	t := r.tail.Load()
	return int(t - h)
}

// Slot returns the next free slot for in-place filling, or nil if the ring is
// full. It does not publish anything: the slot becomes visible to the consumer
// only after Publish. Calling Slot again without Publish returns the same slot.
// Producer only.
func (r *Ring[T]) Slot() *T { return r.slot(0) }

// slot returns the next free slot provided that more than reserve slots are
// free. The reserve is how non-critical traffic leaves headroom for critical
// events.
func (r *Ring[T]) slot(reserve uint64) *T {
	t := r.ptail
	if t-r.headCache+reserve >= r.size {
		r.headCache = r.head.Load()
		if t-r.headCache+reserve >= r.size {
			return nil
		}
	}
	return &r.buf[t&r.mask]
}

// Publish makes the slot returned by the last Slot call visible to the
// consumer. Producer only.
func (r *Ring[T]) Publish() {
	r.ptail++
	r.tail.Store(r.ptail) // release: orders the slot writes before the new tail
}

// producerLen is the exact occupancy as seen by the producer.
func (r *Ring[T]) producerLen() uint64 { return r.ptail - r.head.Load() }

// Offer copies v into the next free slot and publishes it. Returns false if
// the ring is full. Producer only.
func (r *Ring[T]) Offer(v T) bool {
	s := r.slot(0)
	if s == nil {
		return false
	}
	*s = v
	r.Publish()
	return true
}

// Claim returns up to max readable slots as at most two contiguous segments
// (the second one is non-empty only when the range wraps around the end of the
// buffer). The slots stay owned by the consumer until Release. Consumer only.
func (r *Ring[T]) Claim(max int) (a, b []T) {
	if max <= 0 {
		return nil, nil
	}
	h := r.chead
	if h == r.tailCache {
		r.tailCache = r.tail.Load() // acquire: pairs with Publish
		if h == r.tailCache {
			return nil, nil
		}
	}
	n := r.tailCache - h
	if n > uint64(max) {
		n = uint64(max)
	}
	start := h & r.mask
	end := start + n
	if end <= r.size {
		return r.buf[start:end], nil
	}
	return r.buf[start:], r.buf[:end-r.size]
}

// Release hands the first n claimed slots back to the producer. Consumer only.
func (r *Ring[T]) Release(n int) {
	r.chead += uint64(n)
	r.head.Store(r.chead)
}

// Drain moves up to len(dst) elements into dst and zeroes the vacated slots so
// the ring doesn't pin them (important for pointer elements). Use Claim/Release
// instead for large value slots. Consumer only.
func (r *Ring[T]) Drain(dst []T) int {
	a, b := r.Claim(len(dst))
	n := copy(dst, a)
	n += copy(dst[n:], b)
	var zero T
	for i := range a {
		a[i] = zero
	}
	for i := range b {
		b[i] = zero
	}
	if n > 0 {
		r.Release(n)
	}
	return n
}

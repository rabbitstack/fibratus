/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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

import (
	"github.com/bits-and-blooms/bitset"
	"github.com/rabbitstack/fibratus/pkg/util/bitmask"
)

// BitMask sets and evaluates event ID bits in the bitmask.
type BitMask struct {
	bitmask *bitmask.Bitmask
}

// NewBitMask creates a fresh event bitmask.
func NewBitMask() *BitMask {
	bs := &BitMask{bitmask: bitmask.New()}
	return bs
}

// Set puts a new event type bit into the bitmask.
func (b *BitMask) Set(id uint) {
	b.bitmask.Set(id)
}

// Test checks if event type bit exists in the bitmask.
func (b *BitMask) Test(id uint) bool {
	return b.bitmask.IsSet(id)
}

// Clear clears the event type bit in the bitmask.
func (b *BitMask) Clear(i uint) {
	b.bitmask.Clear(i)
}

// BitSetType defines the bitset type
type BitSetType uint8

const (
	// BitmaskBitSet designates the mask-based event id bitset
	BitmaskBitSet BitSetType = iota + 1
	// TypeBitSet designates the uint16 number space event type bitset
	TypeBitSet
	// CategoryBitSet designates the event category bitset
	CategoryBitSet
)

// BitSets contains a collection of bitsets - event id bitmask,
// event type, and category bitsets respectively.
type BitSets struct {
	bitmask *BitMask

	cats  *bitset.BitSet
	types *bitset.BitSet
}

// SetBit sets the bit dictated by the bitset type.
func (b *BitSets) SetBit(bs BitSetType, typ Type) {
	switch bs {
	case BitmaskBitSet:
		if b.bitmask == nil {
			b.bitmask = NewBitMask()
		}
		b.bitmask.Set(typ.ID())

	case TypeBitSet:
		if b.types == nil {
			b.types = bitset.New(uint(MaxTypeID() + 1))
		}
		b.types.Set(uint(typ.HookID()))

	case CategoryBitSet:
		if b.cats == nil {
			b.cats = bitset.New(MaxCategoryIndex + 1)
		}
		b.cats.Set(uint(typ.Category().Index()))
	}
}

// SetCategoryBit toggles the category bit in the bitset.
func (b *BitSets) SetCategoryBit(c Category) {
	if b.cats == nil {
		b.cats = bitset.New(MaxCategoryIndex + 1)
	}
	b.cats.Set(uint(c.Index()))
}

// IsBitSet checks if any of the populated bitsets
// contain the type, event ID, or category bit.
// This method evaluates first the event type bitset.
// The event type bitset should only be initialized
// if all event types pertain to the same category.
// Otherwise, event id bitset and last category bitset
// are tested for respective bits.
func (b *BitSets) IsBitSet(evt *Event) bool {
	if b.types != nil && b.types.Test(uint(evt.Type.HookID())) {
		return true
	}
	return (b.bitmask != nil && b.bitmask.Test(evt.Type.ID())) ||
		(b.cats != nil && b.cats.Test(uint(evt.Category.Index())))
}

func (b *BitSets) IsBitmaskInitialized() bool  { return b.bitmask != nil }
func (b *BitSets) IsTypesInitialized() bool    { return b.types != nil }
func (b *BitSets) IsCategoryInitialized() bool { return b.cats != nil }

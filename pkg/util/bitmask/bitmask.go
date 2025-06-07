/*
 * Copyright 2021-present by Nedim Sabic Sabic
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

package bitmask

// Bitmask is the map-backed bitmask.
// Each bit index i is split into:
//
// wordIdx = i / 64
// bitPos = i % 64
//
// This allows a virtually unbounded sparse bitset over uint64.
type Bitmask struct {
	words map[uint]uint
}

func New() *Bitmask {
	return &Bitmask{
		words: make(map[uint]uint),
	}
}

func (b *Bitmask) Set(i uint) {
	word := i / 64
	bit := i % 64
	b.words[word] |= 1 << bit
}

func (b *Bitmask) Clear(i uint) {
	word := i / 64
	bit := i % 64
	b.words[word] &^= 1 << bit
	if b.words[word] == 0 {
		delete(b.words, word)
	}
}

func (b *Bitmask) IsSet(i uint) bool {
	word := i / 64
	bit := i % 64
	return b.words[word]&(1<<bit) != 0
}

/*
 * Copyright 2021-2026 by Nedim Sabic Sabic
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

package bitmap

// Bitmap is a set of bits backed by a uint64. The type parameter
// T represents the type used to identify bits. It may be any unsigned
// integer type or an alias of one. Valid bit values range from 0 to 63.
type Bitmap[T ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64] uint64

// Has reports whether the bit identified by b is set.
func (s Bitmap[T]) Has(b T) bool {
	return s&(1<<b) != 0
}

// Set sets the bit identified by b.
func (s *Bitmap[T]) Set(b T) {
	*s |= 1 << b
}

// Clear clears the bit identified by b.
func (s *Bitmap[T]) Clear(b T) {
	*s &^= 1 << b
}

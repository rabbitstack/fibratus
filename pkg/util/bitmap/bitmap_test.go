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

import (
	"testing"
)

type Type uint8

const (
	Foo Type = iota
	Bar
	Baz
)

func TestBitmap(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "new bitmap has no bits set",
			run: func(t *testing.T) {
				var s Bitmap[Type]

				for _, typ := range []Type{Foo, Bar, Baz} {
					if s.Has(typ) {
						t.Errorf("Has(%v) = true, want false", typ)
					}
				}
			},
		},
		{
			name: "Set sets a bit",
			run: func(t *testing.T) {
				var s Bitmap[Type]

				s.Set(Foo)

				if !s.Has(Foo) {
					t.Errorf("Has(Foo) = false, want true")
				}
				if s.Has(Bar) {
					t.Errorf("Has(Bar) = true, want false")
				}
			},
		},
		{
			name: "bitmap can set multiple bits",
			run: func(t *testing.T) {
				var s Bitmap[Type]

				s.Set(Foo)
				s.Set(Baz)

				if !s.Has(Foo) {
					t.Errorf("Has(Foo) = false, want true")
				}
				if s.Has(Bar) {
					t.Errorf("Has(Bar) = true, want false")
				}
				if !s.Has(Baz) {
					t.Errorf("Has(Baz) = false, want true")
				}
			},
		},
		{
			name: "Clear clears a bit",
			run: func(t *testing.T) {
				var s Bitmap[Type]

				s.Set(Foo)
				s.Set(Bar)

				s.Clear(Foo)

				if s.Has(Foo) {
					t.Errorf("Has(Foo) = true, want false")
				}
				if !s.Has(Bar) {
					t.Errorf("Has(Bar) = false, want true")
				}
			},
		},
		{
			name: "Clear unset bit is a no-op",
			run: func(t *testing.T) {
				var s Bitmap[Type]

				s.Set(Foo)
				s.Clear(Bar)

				if !s.Has(Foo) {
					t.Errorf("Has(Foo) = false, want true")
				}
			},
		},
		{
			name: "Set same bit twice is idempotent",
			run: func(t *testing.T) {
				var s Bitmap[Type]

				s.Set(Foo)
				s.Set(Foo)

				if !s.Has(Foo) {
					t.Errorf("Has(Foo) = false, want true")
				}
			},
		},
		{
			name: "Clear same bit twice is idempotent",
			run: func(t *testing.T) {
				var s Bitmap[Type]

				s.Set(Foo)
				s.Clear(Foo)
				s.Clear(Foo)

				if s.Has(Foo) {
					t.Errorf("Has(Foo) = true, want false")
				}
			},
		},
		{
			name: "supports bit 63",
			run: func(t *testing.T) {
				type Type64 uint8

				const LastBit Type64 = 63

				var s Bitmap[Type64]

				s.Set(LastBit)

				if !s.Has(LastBit) {
					t.Errorf("Has(63) = false, want true")
				}

				s.Clear(LastBit)

				if s.Has(LastBit) {
					t.Errorf("Has(63) = true after Clear, want false")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.run)
	}
}

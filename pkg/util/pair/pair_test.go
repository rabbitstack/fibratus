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
package pair

import (
	"fmt"
	"reflect"
	"testing"
)

func TestNew(t *testing.T) {
	p := New(uint32(1234), "Run")

	if p.First != 1234 {
		t.Errorf("First = %v, want 1234", p.First)
	}
	if p.Second != "Run" {
		t.Errorf("Second = %q, want %q", p.Second, "Run")
	}

	// the constructor and the composite literal must produce equal values
	if lit := (Pair[uint32, string]{1234, "Run"}); p != lit {
		t.Errorf("New() = %v, want %v", p, lit)
	}
}

func TestUnpack(t *testing.T) {
	a, b := New(42, "answer").Unpack()
	if a != 42 || b != "answer" {
		t.Errorf("Unpack() = (%v, %v), want (42, answer)", a, b)
	}
}

func TestString(t *testing.T) {
	tests := []struct {
		name string
		got  fmt.Stringer
		want string
	}{
		{"int and string", New(1, "a"), "(1, a)"},
		{"zero value", Pair[int, string]{}, "(0, )"},
		{"bool and float", New(true, 1.5), "(true, 1.5)"},
		{"fmt verb", New("x", "y"), "(x, y)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.got.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
			if got := fmt.Sprint(tt.got); got != tt.want {
				t.Errorf("fmt.Sprint() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSwap(t *testing.T) {
	p := New(7, "seven")
	s := Swap(p)

	if s.First != "seven" || s.Second != 7 {
		t.Errorf("Swap() = %v, want (seven, 7)", s)
	}
	if back := Swap(s); back != p {
		t.Errorf("Swap(Swap(p)) = %v, want %v", back, p)
	}
}

func TestComparable(t *testing.T) {
	a := New(uint32(1), "x")
	b := New(uint32(1), "x")
	c := New(uint32(2), "x")

	if a != b {
		t.Error("equal pairs should compare equal")
	}
	if a == c {
		t.Error("different pairs should not compare equal")
	}
}

func TestAsMapKey(t *testing.T) {
	type key = Pair[uint32, string]

	m := make(map[key]int)
	m[New(uint32(100), "Run")] = 1
	m[New(uint32(100), "RunOnce")] = 2
	m[New(uint32(200), "Run")] = 3

	if len(m) != 3 {
		t.Fatalf("len(m) = %d, want 3", len(m))
	}
	if got := m[New(uint32(100), "Run")]; got != 1 {
		t.Errorf("m[(100, Run)] = %d, want 1", got)
	}

	// overwriting an existing key must not grow the map
	m[New(uint32(100), "Run")] = 10
	if len(m) != 3 || m[New(uint32(100), "Run")] != 10 {
		t.Errorf("overwrite failed: len=%d value=%d", len(m), m[New(uint32(100), "Run")])
	}

	if _, ok := m[New(uint32(999), "missing")]; ok {
		t.Error("unexpected hit for missing key")
	}
}

func TestZip(t *testing.T) {
	tests := []struct {
		name string
		as   []int
		bs   []string
		want []Pair[int, string]
	}{
		{"equal length", []int{1, 2}, []string{"a", "b"}, []Pair[int, string]{{1, "a"}, {2, "b"}}},
		{"first longer", []int{1, 2, 3}, []string{"a"}, []Pair[int, string]{{1, "a"}}},
		{"second longer", []int{1}, []string{"a", "b", "c"}, []Pair[int, string]{{1, "a"}}},
		{"first empty", nil, []string{"a"}, nil},
		{"both empty", nil, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Zip(tt.as, tt.bs); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Zip() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUnzip(t *testing.T) {
	as, bs := Unzip([]Pair[int, string]{{1, "a"}, {2, "b"}, {3, "c"}})

	if want := []int{1, 2, 3}; !reflect.DeepEqual(as, want) {
		t.Errorf("firsts = %v, want %v", as, want)
	}
	if want := []string{"a", "b", "c"}; !reflect.DeepEqual(bs, want) {
		t.Errorf("seconds = %v, want %v", bs, want)
	}

	as, bs = Unzip[int, string](nil)
	if as != nil || bs != nil {
		t.Errorf("Unzip(nil) = (%v, %v), want (nil, nil)", as, bs)
	}
}

func TestZipUnzipRoundTrip(t *testing.T) {
	as := []int{10, 20, 30}
	bs := []string{"x", "y", "z"}

	gotA, gotB := Unzip(Zip(as, bs))
	if !reflect.DeepEqual(gotA, as) || !reflect.DeepEqual(gotB, bs) {
		t.Errorf("round trip = (%v, %v), want (%v, %v)", gotA, gotB, as, bs)
	}
}

func BenchmarkMapKey(b *testing.B) {
	m := make(map[Pair[uint32, string]]int, 64)
	k := New(uint32(4242), "Run")
	b.ReportAllocs()
	for b.Loop() {
		m[k]++
	}
}

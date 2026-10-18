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

import "fmt"

// Pair holds two values of possibly different types.
//
// The type parameters are unconstrained, which means Pair can hold anything,
// but it is only usable as a map key when both A and B are comparable.
type Pair[A, B any] struct {
	First  A
	Second B
}

// New returns a Pair holding a and b. Unlike a composite literal, New lets the
// compiler infer the type parameters from its arguments.
func New[A, B any](a A, b B) Pair[A, B] {
	return Pair[A, B]{First: a, Second: b}
}

// Unpack returns both elements of the pair, which is handy for assigning them
// to variables in one statement.
func (p Pair[A, B]) Unpack() (A, B) {
	return p.First, p.Second
}

// String implements fmt.Stringer and renders the pair as "(first, second)".
func (p Pair[A, B]) String() string {
	return fmt.Sprintf("(%v, %v)", p.First, p.Second)
}

// Swap returns a new pair with the elements in reverse order. It is a function
// rather than a method because Go methods cannot introduce new type parameters.
func Swap[A, B any](p Pair[A, B]) Pair[B, A] {
	return Pair[B, A]{First: p.Second, Second: p.First}
}

// Zip combines two slices element by element into a slice of pairs. If the
// slices differ in length, the result is truncated to the shorter one.
func Zip[A, B any](as []A, bs []B) []Pair[A, B] {
	n := min(len(as), len(bs))
	if n == 0 {
		return nil
	}
	pairs := make([]Pair[A, B], n)
	for i := range n {
		pairs[i] = Pair[A, B]{First: as[i], Second: bs[i]}
	}
	return pairs
}

// Unzip splits a slice of pairs into two slices holding the first and second
// elements respectively. It is the inverse of Zip.
func Unzip[A, B any](pairs []Pair[A, B]) ([]A, []B) {
	if len(pairs) == 0 {
		return nil, nil
	}
	as := make([]A, len(pairs))
	bs := make([]B, len(pairs))
	for i, p := range pairs {
		as[i], bs[i] = p.First, p.Second
	}
	return as, bs
}

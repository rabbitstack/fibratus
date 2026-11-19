/*
 * Copyright 2020-2021 by Nedim Sabic Sabic
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

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWalkVisitsAncestorsFromParent(t *testing.T) {
	root := &PS{PID: 1, Name: "root"}
	mid := &PS{PID: 2, Name: "mid", Parent: root}
	leaf := &PS{PID: 3, Name: "leaf", Parent: mid}

	var names []string
	Walk(func(ps *PS) { names = append(names, ps.Name) }, leaf)
	assert.Equal(t, []string{"mid", "root"}, names)

	names = nil
	Walk(func(ps *PS) { names = append(names, ps.Name) }, root)
	assert.Equal(t, 0, len(names))

	// nil is tolerated
	Walk(func(ps *PS) { t.Error("must not be invoked") }, nil)
}

func TestWalkStopsOnCycles(t *testing.T) {
	// a process that is its own parent
	self := &PS{PID: 1, Name: "self"}
	self.Parent = self

	var names []string
	Walk(func(ps *PS) { names = append(names, ps.Name) }, self)
	assert.Equal(t, 0, len(names))

	// pid reuse can produce longer cycles: a -> b -> c -> b
	a := &PS{PID: 1, Name: "a"}
	b := &PS{PID: 2, Name: "b"}
	c := &PS{PID: 3, Name: "c"}
	a.Parent, b.Parent, c.Parent = b, c, b

	names = nil
	Walk(func(ps *PS) { names = append(names, ps.Name) }, a)
	assert.Equal(t, []string{"b", "c"}, names)
}

//go:build filament && windows
// +build filament,windows

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

package cpython

/*
#include "api.h"
*/
import "C"

// Tuple represents the Python tuple sequence object.
type Tuple struct {
	*PyObject
}

// NewTuple constructs a new tuple object of the provided size.
func NewTuple(size int) *Tuple {
	return &Tuple{PyObject: &PyObject{rawptr: C.PyTuple_New(C.Py_ssize_t(size))}}
}

// Set inserts a reference to object at specified position of the tuple.
func (t *Tuple) Set(pos int, ob *PyObject) {
	C.PyTuple_SetItem(t.rawptr, C.Py_ssize_t(pos), ob.rawptr)
}

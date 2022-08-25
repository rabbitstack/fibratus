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

// Dict represents the abstraction over the Python dictionary object.
type Dict struct {
	*PyObject
}

// NewDict constructs a new empty dictionary object.
func NewDict() *Dict {
	return &Dict{PyObject: &PyObject{rawptr: C.PyDict_New()}}
}

// NewDictFromObject constructs a new dictionary object from the existing dictionary.
func NewDictFromObject(o *PyObject) *Dict {
	return &Dict{PyObject: o}
}

// Insert inserts a value into the dictionary indexed with a key. Key must be hashable, otherwise TypeError is raised.
func (d *Dict) Insert(k, v *PyObject) {
	C.PyDict_SetItem(d.rawptr, k.rawptr, v.rawptr)
}

// Get returns the object from dictionary with the provided key. Returns a null object if the key key is not present,
// but without setting an exception.
func (d *Dict) Get(k *PyObject) *PyObject {
	return &PyObject{rawptr: C.PyDict_GetItem(d.rawptr, k.rawptr)}
}

// Object returns the underlying Python object reference.
func (d *Dict) Object() *PyObject {
	return d.PyObject
}

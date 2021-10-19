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

package cpython

/*
#include "api.h"
*/
import "C"

type List struct {
	*PyObject
}

// NewList return a new list of length len on success, or NULL on failure.
//
// If length is greater than zero, the returned list object’s items are set to NULL.
// Thus you cannot use abstract API functions such as PySequence_SetItem() or expose
// the object to Python code before setting all items to a real object with PyList_SetItem().
func NewList(sz int) *List {
	return &List{PyObject: &PyObject{rawptr: C.PyList_New(C.Py_ssize_t(sz))}}
}

// Append adds the object item at the end of list list. Analogous to list.append(item).
func (l *List) Append(item *PyObject) {
	C.PyList_Append(l.rawptr, item.rawptr)
}

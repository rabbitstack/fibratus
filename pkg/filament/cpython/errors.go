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
import (
	"errors"
	"sync"
	"unsafe"
)

var once sync.Once
var formatException *PyObject

// FetchErr retrieves the error indicator into three variables whose addresses are passed. If the error indicator is not
// set, set all three variables to NULL. If it is set, it will be cleared and you own a reference to each object retrieved.
// The value and traceback object may be NULL even when the type object is not.
func FetchErr() error {
	if C.PyErr_Occurred() == nil {
		// error indicator not set, nothing to do
		return nil
	}

	exc := &PyObject{}
	val := &PyObject{}
	traceback := &PyObject{}
	defer exc.DecRef()
	defer val.DecRef()
	defer traceback.DecRef()

	C.PyErr_Fetch(&exc.rawptr, &val.rawptr, &traceback.rawptr)
	//  normalize exception values as per python C API
	C.PyErr_NormalizeException(&exc.rawptr, &val.rawptr, &traceback.rawptr)

	if !traceback.IsNull() {
		once.Do(func() {
			tb, _ := NewModule("traceback")
			if tb != nil {
				formatException, _ = tb.GetAttrString("format_exception")
			}
		})
		if !formatException.IsNull() {
			ob := formatException.Call(exc, val, traceback)
			if !ob.IsNull() {
				defer ob.DecRef()
				return errors.New(ob.String())
			}
		}
		return errors.New("can't format traceback exception")
	}
	if !val.IsNull() {
		return errors.New(val.String())
	}
	if !exc.IsNull() {
		return errors.New(exc.String())
	}
	return nil
}

// SetRuntimeErr raises the Python Runtime Error.
func SetRuntimeErr(message string) {
	msg := C.CString(message)
	defer C.free(unsafe.Pointer(msg))
	C.PyErr_SetString(C.PyExc_RuntimeError, msg)
}

// ClearError clears the error indicator.
func ClearError() {
	C.PyErr_Clear()
}

// CheckSignals checks the signal queue.
func CheckSignals() bool {
	return C.PyErr_CheckSignals() == -1
}

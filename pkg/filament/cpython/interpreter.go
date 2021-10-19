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
#cgo pkg-config: python-310

#include "api.h"

*/
import "C"
import (
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// ErrPyInit signals that an error ocurred while initializing the Python interpreter
var ErrPyInit = errors.New("couldn't initialize the Python interpreter")

// Initialize initializes the Python interpreter and its global interpreter lock (GIL).
func Initialize() error {
	if C.Py_IsInitialized() == 0 {
		// initialize the interpreter without signal handlers
		C.Py_InitializeEx(0)
	}
	if C.Py_IsInitialized() == 0 {
		return ErrPyInit
	}

	// this calls into PyDateTime_IMPORT macro to initialize the PyDateTimeAPI
	C.Py_DateTimeImport()

	if err := initializeIPFnAndClasses(); err != nil {
		log.Warn(err)
	}

	return nil
}

// Finalize undos all initializations made by Initialize() and subsequent use of Python/C API functions,
// and destroys all sub-interpreters that were created and not yet destroyed since the last call to Initialize().
// Ideally, this frees all memory allocated by the Python interpreter.
func Finalize() {
	C.Py_Finalize()
}

// AddPythonPath adds a new path to the PYTHONPATH environment variable.
func AddPythonPath(path string) {
	syspath := C.CString("path")
	defer C.free(unsafe.Pointer(syspath))
	newPath := PyUnicodeFromString(path)
	defer newPath.DecRef()
	C.PyList_Append(C.PySys_GetObject(syspath), newPath.rawptr)
}

// SetPath sets the default module search path. If this function is called before Py_Initialize(), then Py_GetPath()
// won’t attempt to compute a default search path but uses the one provided instead. This is useful if Python is
// embedded by an application that has full knowledge of the location of all modules.
func SetPath(path string) {
	w, err := syscall.UTF16FromString(path)
	if err != nil {
		return
	}
	C.Py_SetPath((*C.wchar_t)(&w[0]))
}

// SetSysArgv sets sys.argv based on argc and argv. These parameters are similar to those passed to
// the program’s main() function with the difference that the first entry should refer to the script
// file to be executed rather than the executable hosting the Python interpreter. If there isn’t a
// script that will be run, the first entry in argv can be an empty string. If this function fails
// to initialize sys.argv, a fatal condition is signalled using Py_FatalError().
func SetSysArgv(args []string) {
	argc := C.int(len(args))
	argv := make([]*C.wchar_t, argc)
	for i, arg := range args {
		argv[i] = newWarg(arg)
	}
	C.PySys_SetArgvEx(argc, (**C.wchar_t)(unsafe.Pointer(&argv[0])), 0)
}

func newWarg(arg string) *C.wchar_t {
	carg := C.CString(arg)
	defer C.free(unsafe.Pointer(carg))

	warg := C.Py_DecodeLocale(carg, nil)
	if warg == nil {
		return nil
	}
	// Py_DecodeLocale requires a call to PyMem_RawFree to free the memory
	defer C.PyMem_RawFree(unsafe.Pointer(warg))
	return warg
}

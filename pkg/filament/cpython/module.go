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
#include <string.h>
#include "api.h"
*/
import "C"
import (
	"fmt"
	"syscall"
	"unsafe"
)

// Module encapsulates the Python module.
type Module struct {
	*PyObject
	name string
}

// NewModule imports a module leaving the globals and locals arguments set to NULL and level set to 0. When the name argument contains
// a dot (when it specifies a submodule of a package), the fromlist argument is set to the list ['*'] so that the return
// value is the named module rather than the top-level package containing it as would otherwise be the case.
// (Unfortunately, this has an additional side effect when name in fact specifies a subpackage instead of a submodule:
// the submodules specified in the package’s __all__ variable are loaded.) Return a new reference to the imported module,
// or NULL with an exception set on failure. A failing import of a module doesn't leave the module in sys.modules.
func NewModule(name string) (*Module, error) {
	n := C.CString(name)
	defer C.free(unsafe.Pointer(n))
	mod := C.PyImport_ImportModule(n)
	if mod == nil {
		return nil, fmt.Errorf("couldn't import %q module", name)
	}
	return &Module{
		PyObject: &PyObject{rawptr: mod},
		name:     name,
	}, nil
}

// MethFlags is the type alias for the method flags
type MethFlags int

const (
	// MethVarArgs indicates that the method or function accepts positional arguments
	MethVarArgs MethFlags = C.METH_VARARGS
	// MethKeyWords indicates that the method or function accepts keyword arguments
	MethKeyWords MethFlags = C.METH_KEYWORDS
	// MethNoArgs indicates that the method or function accepts no arguments
	MethNoArgs MethFlags = C.METH_NOARGS
)

// DefaultMethFlags represents the default method flags
var DefaultMethFlags = MethVarArgs | MethKeyWords

// declared globally to guard PyMethodDef structures from the garbage collector
var defs = map[string]*C.PyMethodDef{}

// RegisterFn anchors the function to this module. The callable Python object is built from the method definition
// that specifies the function name, the args expected by the function and the pointer to the Go callback.
func (m *Module) RegisterFn(name string, fn interface{}, flags MethFlags) error {
	n := C.CString(name)
	defer C.free(unsafe.Pointer(n))
	defs[name] = &C.PyMethodDef{
		ml_name:  n,
		ml_meth:  (C.PyCFunction)(unsafe.Pointer(syscall.NewCallback(fn))),
		ml_flags: C.int(flags),
	}
	mod := C.CString(m.name)
	defer C.free(unsafe.Pointer(mod))
	f := C.PyCFunction_NewEx((*C.PyMethodDef)(unsafe.Pointer(defs[name])), m.rawptr, C.PyUnicode_FromString(mod))
	if f == nil {
		return fmt.Errorf("unable to attach the %s function to the %s module", name, m.name)
	}
	return m.SetAttrString(name, f)
}

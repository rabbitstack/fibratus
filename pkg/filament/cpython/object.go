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
import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"
)

var errTypeNotList = errors.New("couldn't parse the argument. It is probably not a list")

// PyRawObject is the type alias for the raw Python object pointer.
type PyRawObject *C.PyObject

// PyArgs represents the alias for the Python positional arguments.
type PyArgs uintptr

// PyKwargs represents the alias for the Python keyword arguments.
type PyKwargs uintptr

// GetInt returns the nth positional argument as an integer.
func (args PyArgs) GetInt(n uint8) int {
	return int(C.PyArg_ParseInt((*C.PyObject)(unsafe.Pointer(args)), C.int(n)))
}

// GetString returns the nth positional argument as a string.
func (args PyArgs) GetString(n uint8) string {
	return fromRawOb(C.PyArg_ParseString((*C.PyObject)(unsafe.Pointer(args)), C.int(n))).String()
}

// GetStringSlice returns the nth argument as a slice of string values.
func (args PyArgs) GetStringSlice(n uint8) ([]string, error) {
	ob := C.PyArg_ParseList((*C.PyObject)(unsafe.Pointer(args)), C.int(n))
	if ob == nil {
		return nil, errTypeNotList
	}
	l := int(C.PyList_Size(ob))
	s := make([]string, l)
	for i := 0; i < l; i++ {
		item := C.PyList_GetItem(ob, C.longlong(i))
		if item == nil {
			continue
		}
		isUnicode := bool(C.Py_IsUnicode(item))
		if !isUnicode {
			continue
		}
		s[i] = fromRawOb(item).String()
	}
	return s, nil
}

// GetSlice returns the nth argument as a slice of generic values.
func (args PyArgs) GetSlice(n uint8) ([]interface{}, error) {
	ob := C.PyArg_ParseList((*C.PyObject)(unsafe.Pointer(args)), C.int(n))
	if ob == nil {
		return nil, errTypeNotList
	}
	l := int(C.PyList_Size(ob))
	if l < 0 {
		return nil, nil
	}
	s := make([]interface{}, l)
	for i := 0; i < l; i++ {
		item := C.PyList_GetItem(ob, C.longlong(i))
		if item == nil {
			continue
		}
		switch {
		case bool(C.Py_IsUnicode(item)):
			s[i] = fromRawOb(item).String()
		case bool(C.Py_IsInteger(item)):
			s[i] = fromRawOb(item).Int()
		case bool(C.Py_IsDateTime(item)):
			s[i] = fromRawOb(item).Time()
		default:
			if ipv4Class != nil {
				if !ipv4Class.IsNull() && C.PyObject_IsInstance(item, ipv4Class.rawptr) > 0 {
					s[i] = net.ParseIP(fromRawOb(item).String())
				}
			}
			if ipv6Class != nil {
				if !ipv6Class.IsNull() && C.PyObject_IsInstance(item, ipv6Class.rawptr) > 0 {
					s[i] = net.ParseIP(fromRawOb(item).String())
				}
			}
		}
	}
	return s, nil
}

// PyArgsParseKeywords parses tuple and keywords arguments.
func PyArgsParseKeywords(args PyArgs, kwargs PyKwargs, kwlist []string) (string, string, string, []string) {
	var (
		ob1 *C.PyObject
		ob2 *C.PyObject
		ob3 *C.PyObject
		ob4 *C.PyObject
	)

	klist := make([]*C.char, len(kwlist)+1)

	for i, k := range kwlist {
		klist[i] = C.CString(k)
		defer C.free(unsafe.Pointer(klist[i]))
	}

	C.PyArg_ParseKeywords(
		(*C.PyObject)(unsafe.Pointer(args)),
		(*C.PyObject)(unsafe.Pointer(kwargs)),
		&klist[0],
		(**C.PyObject)(unsafe.Pointer(&ob1)),
		(**C.PyObject)(unsafe.Pointer(&ob2)),
		(**C.PyObject)(unsafe.Pointer(&ob3)),
		(**C.PyObject)(unsafe.Pointer(&ob4)),
	)

	return fromRawOb(ob1).String(), fromRawOb(ob2).String(), fromRawOb(ob3).String(), fromRawOb(ob4).StringSlice()
}

// PyObject is the main abstraction for manipulating the native CPython objects.
type PyObject struct {
	rawptr *C.PyObject
}

// NewPyNone creates a new none Python object.
func NewPyNone() *C.PyObject {
	return C.Py_None
}

// NewPyLong creates a new 64-bit signed integer Python object.
func NewPyLong(v int64) *C.PyObject {
	return C.PyLong_FromLongLong(C.i64(v))
}

// NewPyObjectFromValue builds a new Python object based on the underlying interface type.
func NewPyObjectFromValue(value interface{}) *PyObject {
	var ob *C.PyObject
	switch v := value.(type) {
	case int8:
		ob = C.PyChar_FromChar(C.i8(v))
	case uint8:
		ob = C.PyChar_FromUnsignedChar(C.u8(v))
	case int16:
		ob = C.PyShort_FromShort(C.i16(v))
	case uint16:
		ob = C.PyShort_FromUnsignedShort(C.u16(v))
	case int32:
		ob = C.PyLong_FromLong(C.i32(v))
	case uint32:
		ob = C.PyLong_FromUnsignedLong(C.u32(v))
	case int64:
		ob = C.PyLong_FromLongLong(C.i64(v))
	case uint64:
		ob = C.PyLong_FromUnsignedLongLong(C.u64(v))
	case string:
		ob = PyUnicodeFromString(v).asRaw()
	case time.Time:
		ob = C.PyTime_FromDateTime(C.int(v.Year()), C.int(v.Month()), C.int(v.Day()), C.int(v.Hour()), C.int(v.Minute()), C.int(v.Second()), C.int(v.Nanosecond()/1000))
	case net.IP:
		if !ipaddressFn.IsNull() {
			ob = ipaddressFn.Call(PyUnicodeFromString(v.String())).asRaw()
		} else {
			ob = PyUnicodeFromString(v.String()).asRaw()
		}
	case func(arg1, arg2 PyArgs) PyRawObject:
		n := C.CString("func")
		defer C.free(unsafe.Pointer(n))
		mdef := &C.PyMethodDef{
			ml_name:  n,
			ml_meth:  (C.PyCFunction)(unsafe.Pointer(syscall.NewCallback(v))),
			ml_flags: C.int(DefaultMethFlags),
		}
		ob = C.PyCFunction_NewEx((*C.PyMethodDef)(unsafe.Pointer(mdef)), nil, C.PyUnicode_FromString(n))
	}
	return &PyObject{rawptr: ob}
}

// fromRawOb builds a new Python object from the raw pointer.
func fromRawOb(ob *C.PyObject) *PyObject { return &PyObject{rawptr: ob} }

// DecRef decrements the reference count for object o. If the object is NULL, nothing happens. If the reference count
// reaches zero, the object’s type’s deallocation function (which must not be NULL) is invoked.
func (ob *PyObject) DecRef() {
	if ob != nil || ob.rawptr == nil {
		return
	}
	C.Py_DecRef(ob.rawptr)
}

// IncRef increment the reference count for object o. The object may be NULL, in which case this method has no effect.
func (ob *PyObject) IncRef() {
	if ob != nil && ob.rawptr == nil {
		return
	}
	C.Py_IncRef(ob.rawptr)
}

// IsNull determines whether this object's instance is null.
func (ob *PyObject) IsNull() bool {
	if ob == nil {
		return true
	}
	return ob.rawptr == nil
}

func (ob *PyObject) asRaw() *C.PyObject {
	return ob.rawptr
}

// SetAttrString set the value of the attribute provided for this object to the specified value.
func (ob *PyObject) SetAttrString(name string, value *C.PyObject) error {
	attr := C.CString(name)
	defer C.free(unsafe.Pointer(attr))
	err := int(C.PyObject_SetAttrString(ob.rawptr, attr, value))
	if err == -1 {
		return fmt.Errorf("couldn't set the value of the %q attribute", name)
	}
	return nil
}

// GetAttrString retrieves an attribute named from object the object. Returns an error if the attribute can't be fetched.
func (ob *PyObject) GetAttrString(name string) (*PyObject, error) {
	attr := C.CString(name)
	defer C.free(unsafe.Pointer(attr))
	v := C.PyObject_GetAttrString(ob.rawptr, attr)
	if v == nil {
		return nil, fmt.Errorf("couldn't get the %q attribute", name)
	}
	return &PyObject{rawptr: v}, nil
}

// HasAttr determines if the Python object has the specified attribute.
func (ob *PyObject) HasAttr(name string) bool {
	attr := C.CString(name)
	defer C.free(unsafe.Pointer(attr))
	return C.PyObject_HasAttrString(ob.rawptr, attr) > 0
}

var encoding = C.CString("utf-8")
var codecErrors = C.CString("strict")

// String encodes an Unicode object and returns the result as a Python bytes object converted to the Go string.
func (ob *PyObject) String() string {
	if ob.rawptr == nil {
		return ""
	}
	repr := C.PyObject_Str(ob.rawptr)
	if repr == nil {
		return ""
	}
	defer C.Py_DecRef(repr)
	s := C.PyUnicode_AsEncodedString(repr, encoding, codecErrors)
	if s == nil {
		return "invalid Unicode string"
	}
	defer C.Py_DecRef(s)
	return C.GoString(C.PyBytes_AsString(s))
}

// StringSlice returns this object as a string slice.
func (ob *PyObject) StringSlice() []string {
	if ob.rawptr == nil {
		return []string{}
	}
	l := int(C.PyList_Size(ob.asRaw()))
	if l < 0 {
		return nil
	}
	s := make([]string, l)
	for i := 0; i < l; i++ {
		item := C.PyList_GetItem(ob.asRaw(), C.longlong(i))
		if item == nil {
			continue
		}
		isUnicode := bool(C.Py_IsUnicode(item))
		if !isUnicode {
			continue
		}
		s[i] = fromRawOb(item).String()
	}
	return s
}

// Uint32 returns an uint32 integer from the raw Python object.
func (ob *PyObject) Uint32() uint32 {
	return uint32(C.PyLong_AsUnsignedLong(ob.rawptr))
}

// Uint64 returns an uint64 integer from the raw Python object.
func (ob *PyObject) Uint64() uint64 {
	return uint64(C.PyLong_AsUnsignedLongLong(ob.rawptr))
}

// Int returns an integer from the raw Python object.
func (ob *PyObject) Int() int {
	return int(C.PyLong_AsUnsignedLongLong(ob.rawptr))
}

// Time returns the time from the raw Python object.
func (ob *PyObject) Time() time.Time {
	year := int(C.PyDate_GetYear((*C.PyObject)(unsafe.Pointer(ob))))
	month := int(C.PyDate_GetMonth((*C.PyObject)(unsafe.Pointer(ob))))
	day := int(C.PyDate_GetDay((*C.PyObject)(unsafe.Pointer(ob))))
	hour := int(C.PyDate_GetHour((*C.PyObject)(unsafe.Pointer(ob))))
	minute := int(C.PyDate_GetMinute((*C.PyObject)(unsafe.Pointer(ob))))
	second := int(C.PyDate_GetSecond((*C.PyObject)(unsafe.Pointer(ob))))
	microsecond := int(C.PyDate_GetMicroSecond((*C.PyObject)(unsafe.Pointer(ob))))
	return time.Date(year, time.Month(month), day, hour, minute, second, microsecond*1000, time.Local)
}

// Type returns the Python type representation.
func (ob *PyObject) Type() string {
	return C.GoString(C.Py_Type(ob.rawptr))
}

// IsCallable determines if the object is callable.
func (ob *PyObject) IsCallable() bool {
	return C.PyCallable_Check(ob.rawptr) > 0
}

// CallableArgCount returns the number of arguments declared in the callable Python object.
func (ob *PyObject) CallableArgCount() uint32 {
	fnCode, err := ob.GetAttrString("__code__")
	if err != nil || fnCode.IsNull() {
		return 0
	}
	defer fnCode.DecRef()
	count, err := fnCode.GetAttrString("co_argcount")
	if err != nil {
		return 0
	}
	defer count.DecRef()
	return count.Uint32()
}

// Call calls a callable Python object with arguments given by the tuple args. If no arguments are needed, then args
// may be NULL. Returns the result of the call on success, or a null reference on failure.
func (ob *PyObject) Call(args ...*PyObject) *PyObject {
	if ob.rawptr == nil {
		return nil
	}
	if len(args) == 0 {
		return &PyObject{rawptr: C.PyObject_CallObject(ob.rawptr, nil)}
	}
	tuple := NewTuple(len(args))
	for pos, arg := range args {
		tuple.Set(pos, arg)
	}
	defer tuple.DecRef()
	r := C.PyObject_CallObject(ob.rawptr, tuple.rawptr)
	return &PyObject{rawptr: r}
}

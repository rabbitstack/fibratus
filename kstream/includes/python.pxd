# Copyright 2016 by Nedim Sabic (RabbitStack)
# http://rabbitstack.github.io
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from cpython.ref cimport PyObject
from libc.stddef cimport wchar_t
from .windows cimport WCHAR, CHAR, BYTE, ULONGLONG, LONGLONG, ULONG, LONG, SHORT, USHORT, ntohs, htonl, inet_ntoa, \
    in_addr, FLOAT, DOUBLE
from .string cimport wstring, sprintf
from cython.operator cimport dereference as deref

cdef extern from "python.h":
    PyObject* PyUnicode_FromString(const char* u) nogil
    PyObject* PyUnicode_FromWideChar (wchar_t* w, Py_ssize_t size) nogil
    wchar_t* PyUnicode_AsWideCharString(PyObject* unicode, Py_ssize_t* size) nogil
    long PyLong_AsLong(PyObject *obj) nogil
    PyObject* Py_BuildValue(char* format, ...) nogil

    PyObject* PyTuple_New(Py_ssize_t len) nogil
    PyObject* PyTuple_GetItem(PyObject* p, Py_ssize_t pos) nogil
    int PyTuple_SetItem(PyObject* p, Py_ssize_t pos, PyObject* o) nogil

    void Py_XDECREF(PyObject* o) nogil
    void Py_XINCREF(PyObject* o)

    void PyMem_Free(void *p) nogil


cdef inline PyObject* _unicode(wchar_t* wchars) nogil:
    return PyUnicode_FromWideChar(wchars, -1)


cdef inline PyObject* _ansi(char* chars) nogil:
    return PyUnicode_FromString(chars)


cdef inline PyObject* _unicodec(void* buf) nogil:
    return Py_BuildValue('u', (<WCHAR*>buf)[0])


cdef inline PyObject* _ansic(void* buf) nogil:
    return Py_BuildValue('s', (<CHAR*>buf)[0])


cdef inline PyObject* _i8(void* buf) nogil:
    return Py_BuildValue('h', (<CHAR*>buf)[0])


cdef inline PyObject* _u8(void* buf) nogil:
    return Py_BuildValue('b', (<BYTE*>buf)[0])


cdef inline PyObject* _u8_hex(void* buf) nogil:
    cdef char hx[200]
    sprintf(hx, "%02x", (<SHORT*>buf)[0])
    return _ansi(hx)


cdef inline PyObject* _i16_hex(void* buf) nogil:
    cdef char hx[200]
    sprintf(hx, "%02x", (<CHAR*>buf)[0])
    return _ansi(hx)


cdef inline PyObject* _i64_hex(void* buf) nogil:
    cdef char hx[200]
    sprintf(hx, "%02x", (<ULONGLONG*>buf)[0])
    return _ansi(hx)


cdef inline PyObject* _i64(void* buf) nogil:
    return Py_BuildValue('i', (<LONGLONG*>buf)[0])


cdef inline PyObject* _u64(void* buf) nogil:
    return Py_BuildValue('i', (<ULONGLONG*>buf)[0])


cdef inline PyObject* _i32(void* buf) nogil:
    return Py_BuildValue('i', (<LONG*>buf)[0])


cdef inline PyObject* _i32_hex(void* buf) nogil:
    cdef char hx[200]
    sprintf(hx, "0x%x", (<ULONG*>buf)[0])
    return _ansi(hx)


cdef inline PyObject* _u32(void* buf) nogil:
    return Py_BuildValue('i', (<ULONG*>buf)[0])


cdef inline PyObject* _i16(void* buf) nogil:
    return Py_BuildValue('h', (<SHORT*>buf)[0])


cdef inline PyObject* _u16(void* buf) nogil:
    return Py_BuildValue('h', (<USHORT*>buf)[0])


cdef inline PyObject* _float(void* buf) nogil:
    return Py_BuildValue('f', (<FLOAT*>buf)[0])


cdef inline PyObject* _double(void* buf) nogil:
    return Py_BuildValue('d', (<DOUBLE*>buf)[0])


cdef inline PyObject* _ntohs(void* buf) nogil:
    return Py_BuildValue('h', ntohs((<USHORT*>buf)[0]))


cdef inline PyObject* _wstring(wstring ws):
    return PyUnicode_FromWideChar(ws.data(), ws.size())


cdef inline wchar_t* _wchar_t(PyObject* o) nogil:
    cdef Py_ssize_t size
    return PyUnicode_AsWideCharString(o, &size)


cdef inline PyObject* ip_addr(void* buf) nogil:
    cdef in_addr addr
    addr.S_un.S_addr = (<ULONG *>buf)[0]
    return Py_BuildValue('s', inet_ntoa(addr))


cdef inline wstring deref_prop(prop_name):
    return deref(new wstring(_wchar_t(<PyObject*>prop_name)))
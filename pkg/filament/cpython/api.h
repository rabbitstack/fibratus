/*
 *	Copyright 2019-2020 by Nedim Sabic
 *	http://rabbitstack.github.io
 *	All Rights Reserved.
 *
 *	Licensed under the Apache License, Version 2.0 (the "License"); you may
 *	not use this file except in compliance with the License. You may obtain
 *	a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 */

#include <Python.h>
#include <string.h>
#include <stdbool.h>
#include "datetime.h"

typedef char i8;
typedef unsigned char u8;
typedef short i16;
typedef unsigned short u16;
typedef long i32;
typedef long long i64;
typedef unsigned long long u64;
typedef unsigned long u32;

/*
Cgo doesn't know how to deal with C macros/variadic functions. This is the main reason we need the wrapper for
some CPython API functions in pure C.
*/

int PyArg_ParseInt(PyObject *args, int n);
PyObject* PyArg_ParseString(PyObject *args, int n);
PyObject* PyArg_ParseList(PyObject *args, int n);

void PyArg_ParseKeywords(PyObject *args, PyObject *kwargs, char *kwlist[], PyObject **ob1,  PyObject **ob2,  PyObject **ob3,  PyObject **ob4);

PyObject* PyTime_FromDateTime(int year, int month, int day, int hour, int minute, int second, int usecond);
PyObject* PyChar_FromChar(char v);
PyObject* PyChar_FromUnsignedChar(unsigned char v);
PyObject* PyShort_FromShort(short v);
PyObject* PyShort_FromUnsignedShort(unsigned short v);

bool Py_IsUnicode(PyObject *ob);
bool Py_IsInteger(PyObject *ob);
bool Py_IsDateTime(PyObject *ob);

void Py_DateTimeImport();

int PyDate_GetYear(PyObject *ob);
int PyDate_GetMonth(PyObject *ob);
int PyDate_GetDay(PyObject *ob);
int PyDate_GetHour(PyObject *ob);
int PyDate_GetMinute(PyObject *ob);
int PyDate_GetSecond(PyObject *ob);
int PyDate_GetMicroSecond(PyObject *ob);

const char* Py_Type(PyObject *ob);
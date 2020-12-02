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

#include "api.h"

int PyArg_ParseInt(PyObject *args, int n) {
    int i;
    int res;
    switch (n) {
    case 1:
        res = PyArg_ParseTuple(args, "i", &i);
        break;
    case 2:
        res = PyArg_ParseTuple(args, "Oi", &i, &i);
        break;
    case 3:
        res = PyArg_ParseTuple(args, "OOi", &i, &i, &i);
        break;
    default:
        return i;
    }
    if (!res) {
        PyErr_SetString(PyExc_ValueError, "argument must be an integer");
        return 0;
    }
    return i;
}

PyObject* PyArg_ParseList(PyObject *args, int n) {
    PyObject *ob;
    int res;
    switch (n) {
    case 1:
        res = PyArg_ParseTuple(args, "O!", &PyList_Type, &ob);
        break;
    case 2:
        res = PyArg_ParseTuple(args, "OO!", &ob, &PyList_Type, &ob);
        break;
    case 3:
        res = PyArg_ParseTuple(args, "OOO!", &ob, &ob, &PyList_Type, &ob);
        break;
    default:
        return NULL;
    }
    if (!res) {
        PyErr_SetString(PyExc_ValueError, "argument must be a list");
        return NULL;
    }
    return ob;
}

PyObject* PyArg_ParseString(PyObject *args, int n) {
    PyObject *ob;
    int res;
    switch (n) {
    case 1:
        res = PyArg_ParseTuple(args, "U", &ob);
        break;
    case 2:
        res = PyArg_ParseTuple(args, "OU", &ob, &ob);
        break;
    case 3:
        res = PyArg_ParseTuple(args, "OOU", &ob, &ob, &ob);
        break;
    default:
        return NULL;
    }
    if (!res) {
        PyErr_SetString(PyExc_ValueError, "argument must be a string");
        return NULL;
    }
    return ob;
}

void PyArg_ParseKeywords(PyObject *args, PyObject *kwargs, char *kwlist[], PyObject **ob1,  PyObject **ob2,  PyObject **ob3,  PyObject **ob4) {
    int res;

    res = PyArg_ParseTupleAndKeywords(args,
                                      kwargs,
                                      "OO|$OO", kwlist,
                                      ob1, ob2, ob3, ob4);
    if (!res) {
        PyErr_SetString(PyExc_ValueError, "parse keywords failed");
    }
}

PyObject* PyTime_FromDateTime(int year, int month, int day, int hour, int minute, int second, int usecond) {
    return PyDateTime_FromDateAndTime(year, month, day, hour, minute, second, usecond);
}

PyObject* PyChar_FromChar(char v) {
    return Py_BuildValue("b", v);
}

PyObject* PyChar_FromUnsignedChar(unsigned char v) {
    return Py_BuildValue("B", v);
}

PyObject* PyShort_FromShort(short v) {
    return Py_BuildValue("h", v);
}

PyObject* PyShort_FromUnsignedShort(unsigned short v) {
    return Py_BuildValue("H", v);
}

bool Py_IsUnicode(PyObject *ob) {
    if (ob == NULL)
      return false;
    return PyUnicode_CheckExact(ob);
}

bool Py_IsInteger(PyObject *ob) {
    if (ob == NULL)
       return false;
    return PyLong_CheckExact(ob);
}

void Py_DateTimeImport() {
    PyDateTime_IMPORT;
}


bool Py_IsDateTime(PyObject *ob) {
    if (ob == NULL)
       return false;
    return PyDateTime_CheckExact(ob);
}

const char* Py_Type(PyObject *ob) {
    return Py_TYPE(ob)->tp_name;
}

int PyDate_GetYear(PyObject *ob) {
    return PyDateTime_GET_YEAR(ob);
}
int PyDate_GetMonth(PyObject *ob) {
    return PyDateTime_GET_MONTH(ob);
}
int PyDate_GetDay(PyObject *ob) {
    return PyDateTime_GET_DAY(ob);
}
int PyDate_GetHour(PyObject *ob) {
    return PyDateTime_DATE_GET_HOUR(ob);
}
int PyDate_GetMinute(PyObject *ob) {
    return PyDateTime_DATE_GET_MINUTE(ob);
}
int PyDate_GetSecond(PyObject *ob) {
    return PyDateTime_DATE_GET_SECOND(ob);
}
int PyDate_GetMicroSecond(PyObject *ob) {
    return PyDateTime_DATE_GET_MICROSECOND(ob);
}
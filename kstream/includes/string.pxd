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

from libc.stddef cimport wchar_t

cdef extern from "wchar.h":
    int wprintf(const wchar_t *, ...) nogil
    int printf( const char* format, ... ) nogil
    int sprintf (char* str, const char* format, ... ) nogil
    long strtol(const char* nptr,  char** endptr, int base) nogil
    long wcstol(const wchar_t* nptr, wchar_t** endptr, int base) nogil
    wchar_t* _wcslwr(wchar_t * s) nogil
    int wcscmp(const wchar_t* string1, const wchar_t* string2) nogil
    size_t wcslen (const wchar_t* wcs)

cdef extern from "<string>" namespace "std" nogil:

    cdef cppclass wstring "std::wstring":
        wstring() except +
        wstring(wchar_t *) except +
        wstring(wchar_t *, size_t) except +
        wstring(wstring&) except +

        const wchar_t* data()
        size_t size()

        int compare(wstring&)


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

cdef extern from "windows.h":
    ctypedef unsigned long ULONG
    ctypedef unsigned char BYTE
    ctypedef unsigned long DWORD
    ctypedef signed int INT32
    ctypedef unsigned short WORD
    ctypedef float FLOAT
    ctypedef double DOUBLE
    ctypedef char CHAR
    ctypedef unsigned char UCHAR
    ctypedef void VOID
    ctypedef void* PVOID
    ctypedef PVOID HANDLE
    ctypedef short SHORT
    ctypedef unsigned short USHORT
    ctypedef long long LONGLONG
    ctypedef char* LPSTR
    ctypedef unsigned long long ULONGLONG
    ctypedef long LONG
    ctypedef void* PVOID
    ctypedef DWORD* LPDWORD
    ctypedef int BOOL
    ctypedef const char* LPCTSTR
    ctypedef const wchar_t* LPWSTR
    ctypedef wchar_t* LPCWSTR
    ctypedef unsigned long long ULONG64
    ctypedef wchar_t* WCHAR
    ctypedef WCHAR* LPTSTR
    ctypedef wchar_t* LPSIDSTR
    ctypedef LPWSTR LPOLESTR
    ctypedef long HRESULT

    enum: ERROR_SUCCESS
    enum: ERROR_CANCELLED

    enum: THREAD_QUERY_INFORMATION
    enum: THREAD_QUERY_LIMITED_INFORMATION

    ctypedef struct GUID:
        DWORD Data1
        WORD Data2
        WORD Data3
        BYTE Data4[8]

    ctypedef const GUID & REFGUID

    ctypedef struct U:
        DWORD LowPart
        LONG HighPart
    ctypedef union LARGE_INTEGER:
        DWORD low"LowPart"
        LONG high "HighPart"
        U u
        LONGLONG QuadPart

    ctypedef struct FILETIME:
        DWORD low_date "dwLowDateTime"
        DWORD high_date "dwHighDateTime"

    ctypedef struct SYSTEMTIME:
        WORD year "wYear"
        WORD month "wMonth"
        WORD day_of_week "wDayOfWeek"
        WORD day "wDay"
        WORD hour "wHour"
        WORD minute "wMinute"
        WORD second "wSecond"
        WORD millis "wMilliseconds"

    ctypedef struct TIME_ZONE_INFORMATION:
        LONG       Bias
        WCHAR      StandardName[32]
        SYSTEMTIME StandardDate
        LONG       StandardBias
        WCHAR      DaylightName[32]
        SYSTEMTIME DaylightDate
        LONG       DaylightBias

    int string_from_guid "StringFromGUID2"(REFGUID guid, LPOLESTR lpsz, int cch) nogil

    BOOL filetime_to_systemtime "FileTimeToSystemTime"(FILETIME *ft, SYSTEMTIME *st) nogil

    BOOL systemtime_to_tz_specific_localtime "SystemTimeToTzSpecificLocalTime"(TIME_ZONE_INFORMATION *zone,
                                                                               SYSTEMTIME *uni_time,
                                                                               SYSTEMTIME *local_time) nogil

    HANDLE open_thread "OpenThread"(DWORD desired_access, BOOL inherit_handle, DWORD thread_id) nogil

    DWORD get_process_id_of_thread "GetProcessIdOfThread"(HANDLE thread) nogil

    BOOL close_handle "CloseHandle"(HANDLE handle) nogil

cdef extern from "winsock.h":
    USHORT ntohs(USHORT netshort) nogil
    ULONG  htonl(ULONG hostlong) nogil

    ctypedef union S_un:
        ULONG S_addr
    ctypedef struct in_addr:
        S_un S_un

    char* inet_ntoa(in_addr addr) nogil


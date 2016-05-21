# Copyright 2015 by Nedim Sabic (RabbitStack)
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

cdef extern from "windows.h":

    # windows type declarations
    ctypedef unsigned long ULONG
    ctypedef unsigned char BYTE
    ctypedef unsigned long DWORD
    ctypedef unsigned short WORD
    ctypedef float FLOAT
    ctypedef double DOUBLE
    ctypedef char CHAR
    ctypedef unsigned char UCHAR
    ctypedef void VOID
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
    ctypedef Py_UNICODE WCHAR
    ctypedef WCHAR* LPTSTR
    ctypedef wchar_t* LPSIDSTR
    ctypedef LPWSTR LPOLESTR
    ctypedef long HRESULT

    enum: ERROR_SUCCESS
    enum: ERROR_CANCELLED

    # GUID structure
    ctypedef struct GUID:
        DWORD Data1
        WORD Data2
        WORD Data3
        BYTE Data4[8]

    # date / time related structs
    ctypedef struct U:
        DWORD LowPart
        LONG HighPart
    ctypedef union LARGE_INTEGER:
        DWORD LowPart
        LONG HighPart
        U u
        LONGLONG QuadPart

    ctypedef struct FILETIME:
        DWORD dwLowDateTime
        DWORD dwHighDateTime

    ctypedef struct SYSTEMTIME:
        WORD wYear
        WORD wMonth
        WORD wDayOfWeek
        WORD wDay
        WORD wHour
        WORD wMinute
        WORD wSecond
        WORD wMilliseconds

    ctypedef struct TIME_ZONE_INFORMATION:
        LONG       Bias
        WCHAR      StandardName[32]
        SYSTEMTIME StandardDate
        LONG       StandardBias
        WCHAR      DaylightName[32]
        SYSTEMTIME DaylightDate
        LONG       DaylightBias

    # GUID to string representation conversion
    int StringFromGUID2(const GUID *guid, LPOLESTR lpsz, int cch)

    # time conversion functions
    BOOL FileTimeToSystemTime(FILETIME *lpFileTime, SYSTEMTIME *lpSystemTime)
    BOOL SystemTimeToTzSpecificLocalTime(TIME_ZONE_INFORMATION *lpTimeZone, SYSTEMTIME *lpUniversalTime,
                                         SYSTEMTIME *lpLocalTime)

    # SID uniquely identifies users or groups
    ctypedef struct SID_IDENTIFIER_AUTHORITY:
        BYTE  Value[6];

    ctypedef struct SID:
        BYTE  Revision
        BYTE  SubAuthorityCount
        SID_IDENTIFIER_AUTHORITY IdentifierAuthority
        DWORD SubAuthority[1]

    ctypedef enum SID_NAME_USE:
        SidTypeUser  = 1
        SidTypeGroup
        SidTypeDomain
        SidTypeAlias
        SidTypeWellKnownGroup
        SidTypeDeletedAccount
        SidTypeInvalid
        SidTypeUnknown
        SidTypeComputer
        SidTypeLabel

    # SID to account name
    BOOL LookupAccountSid(LPCTSTR lpSystemName, SID *lpSid, LPSIDSTR lpName, LPDWORD cchName,
                          LPSIDSTR lpReferencedDomainName,
                          LPDWORD cchReferencedDomainName,
                          SID_NAME_USE *peUse)


cdef extern from "python.h":
    void* PyLong_AsVoidPtr(object)
    PyObject* PyUnicode_FromString(const char *u)
    PyObject* PyUnicode_FromWideChar(wchar_t *w, Py_ssize_t size)

cdef extern from "wchar.h":
    int wprintf(const wchar_t *, ...)

cdef extern from "evntcons.h":

    # ETW struct & constant declarations
    enum: EVENT_HEADER_FLAG_32_BIT_HEADER
    enum: PROCESS_TRACE_MODE_EVENT_RECORD

    ctypedef struct EVENT_TRACE_PROPERTIES:
        pass
    ctypedef struct ETW_BUFFER_CONTEXT:
        UCHAR ProcessorNumber
        UCHAR  Alignment
        USHORT LoggerId

    ctypedef struct EVENT_DESCRIPTOR:
        USHORT    Id
        UCHAR     Version
        UCHAR     Channel
        UCHAR     Level
        UCHAR     Opcode
        USHORT    Task
        ULONGLONG Keyword

    ctypedef struct EVENT_HEADER:
        USHORT Size
        USHORT HeaderType
        USHORT Flags
        USHORT EventProperty
        ULONG ThreadId
        ULONG ProcessId
        LARGE_INTEGER TimeStamp
        GUID ProviderId
        EVENT_DESCRIPTOR EventDescriptor
        ULONG KernelTime
        ULONG UserTime
        ULONGLONG ProcessorTime
        GUID ActivityId

    ctypedef struct LINKAGE:
        USHORT Linkage
        USHORT Reserverd2
    ctypedef struct EVENT_HEADER_EXTENDED_DATA_ITEM:
        USHORT    Reserved1
        USHORT    ExtType
        LINKAGE   Linkage
        USHORT	  DataSize
        ULONGLONG DataPtr

    ctypedef struct EVENT_RECORD:
        EVENT_HEADER EventHeader
        ETW_BUFFER_CONTEXT BufferContext
        USHORT ExtendedDataCount
        USHORT UserDataLength
        EVENT_HEADER_EXTENDED_DATA_ITEM* ExtendedData
        PVOID UserData
        PVOID UserContext

cdef extern from "evntrace.h":

    # event trace consuming functions
    ctypedef VOID (__stdcall *PEVENT_RECORD_CALLBACK) (EVENT_RECORD* EventRecord)

    ctypedef ULONG64 TRACEHANDLE

    enum: INVALID_PROCESSTRACE_HANDLE
    enum: EVENT_TRACE_REAL_TIME_MODE

    ctypedef struct EVENT_TRACE_LOGFILE:
        LPTSTR LogFileName
        LPSTR LoggerName
        ULONG LogFileMode
        ULONG ProcessTraceMode
        PEVENT_RECORD_CALLBACK EventRecordCallback
        PVOID Context

    TRACEHANDLE OpenTrace(EVENT_TRACE_LOGFILE * logfile)

    ULONG CloseTrace(TRACEHANDLE traceHandle)

    ULONG ProcessTrace(TRACEHANDLE* HandleArray,
                       ULONG HandleCount,
                       FILETIME * StartTime,
                       FILETIME * EndTime)

cdef extern from "stdlib.h":
    # standard memory allocation/release
    void free(void* ptr)
    void* malloc(size_t size)

cdef extern from "tdh.h":

    # trace data helper (TDH) function
    # and structure declarations
    ctypedef ULONG TDHAPI

    # event property input types
    ctypedef enum TDH_IN_TYPE:
        TDH_INTYPE_NULL = 0
        TDH_INTYPE_UNICODESTRING = 1
        TDH_INTYPE_ANSISTRING = 2
        TDH_INTYPE_INT8 = 3
        TDH_INTYPE_UINT8 = 4
        TDH_INTYPE_INT16 = 5
        TDH_INTYPE_UINT16 = 6
        TDH_INTYPE_INT32 = 7
        TDH_INTYPE_UINT32 = 8
        TDH_INTYPE_INT64 = 9
        TDH_INTYPE_UINT64 = 10
        TDH_INTYPE_FLOAT = 11
        TDH_INTYPE_DOUBLE = 12
        TDH_INTYPE_BOOLEAN = 13
        TDH_INTYPE_BINARY = 14
        TDH_INTYPE_GUID = 15
        TDH_INTYPE_POINTER = 16
        TDH_INTYPE_FILETIME = 17
        TDH_INTYPE_SYSTEMTIME = 18
        TDH_INTYPE_SID = 19
        TDH_INTYPE_HEXINT32 = 20
        TDH_INTYPE_HEXINT64 = 21
        TDH_INTYPE_COUNTEDSTRING = 300
        TDH_INTYPE_COUNTEDANSISTRING = 301
        TDH_INTYPE_REVERSEDCOUNTEDSTRING = 302
        TDH_INTYPE_REVERSEDCOUNTEDANSISTRING = 303
        TDH_INTYPE_NONNULLTERMINATEDSTRING = 304
        TDH_INTYPE_NONNULLTERMINATEDANSISTRING = 305
        TDH_INTYPE_UNICODECHAR = 306
        TDH_INTYPE_ANSICHAR = 307
        TDH_INTYPE_SIZET = 308
        TDH_INTYPE_HEXDUMP = 309
        TDH_INTYPE_WBEMSID = 310

    # event property output types
    ctypedef enum TDH_OUT_TYPE:
        TDH_OUTTYPE_NULL = 0
        TDH_OUTTYPE_STRING = 1
        TDH_OUTTYPE_DATETIME = 2
        TDH_OUTTYPE_BYTE = 3
        TDH_OUTTYPE_UNSIGNEDBYTE = 4
        TDH_OUTTYPE_SHORT = 5
        TDH_OUTTYPE_UNSIGNEDSHORT  = 6
        TDH_OUTTYPE_INT = 6
        TDH_OUTTYPE_UNSIGNEDINT = 7
        TDH_OUTTYPE_LONG  = 8
        TDH_OUTTYPE_UNSIGNEDLONG = 9
        TDH_OUTTYPE_FLOAT = 10
        TDH_OUTTYPE_DOUBLE = 11
        TDH_OUTTYPE_BOOLEAN = 12
        TDH_OUTTYPE_GUID = 13
        TDH_OUTTYPE_HEXBINARY = 14
        TDH_OUTTYPE_HEXINT8 = 15
        TDH_OUTTYPE_HEXINT16 = 16
        TDH_OUTTYPE_HEXINT32 = 17
        TDH_OUTTYPE_HEXINT64 = 18
        TDH_OUTTYPE_PID  = 19
        TDH_OUTTYPE_TID  = 20
        TDH_OUTTYPE_PORT  = 21
        TDH_OUTTYPE_IPV4  = 22
        TDH_OUTTYPE_IPV6  = 23
        TDH_OUTTYPE_SOCKETADDRESS  = 24
        TDH_OUTTYPE_CIMDATETIME  = 25
        TDH_OUTTYPE_ETWTIME  = 26
        TDH_OUTTYPE_XML  = 27
        TDH_OUTYTPE_ERRORCODE  = 28,
        TDH_OUTTYPE_REDUCEDSTRING = 300

    ctypedef enum PROPERTY_FLAGS:
        PropertyStruct        = 0x1
        PropertyParamLength   = 0x2
        PropertyParamCount    = 0x4
        PropertyWBEMXmlFragment = 0x8
        PropertyParamFixedLength = 0x10


    ctypedef struct NON_STRUCT_TYPE:
        USHORT InType
        USHORT OutType

    ctypedef struct EVENT_PROPERTY_INFO:
        ULONG NameOffset
        NON_STRUCT_TYPE nonStructType

    ctypedef struct TRACE_PROVIDER_INFO:
        GUID ProviderGuid
        USHORT PropertyCount


    ctypedef struct TDH_CONTEXT:
        pass

    ctypedef struct PROPERTY_DATA_DESCRIPTOR:
        ULONGLONG PropertyName
        ULONG     ArrayIndex
        ULONG     Reserved


    ctypedef struct TRACE_EVENT_INFO:
        GUID ProviderGuid
        GUID EventGuid
        ULONG ProviderNameOffset
        ULONG OpcodeNameOffset
        ULONG PropertyCount
        ULONG TopLevelPropertyCount
        EVENT_PROPERTY_INFO EventPropertyInfoArray[1]


    TDHAPI TdhGetEventInformation(EVENT_RECORD* pEvent,
                                  ULONG TdhContextCount,
                                  TDH_CONTEXT* pThdContext,
                                  TRACE_EVENT_INFO* pBuffer,
                                  ULONG *pBufferSize)
    ULONG  TdhGetPropertySize(EVENT_RECORD* pEvent,
                             ULONG TdhContextCount,
                             TDH_CONTEXT* pTdhContext,
                             ULONG PropertyDataCount,
                             PROPERTY_DATA_DESCRIPTOR* pPropertyData,
                             ULONG *pPropertySize)
    ULONG  TdhGetProperty(EVENT_RECORD* pEvent,
                          ULONG TdhContextCount,
                          TDH_CONTEXT* pTdhContext,
                          ULONG PropertyDataCount,
                          PROPERTY_DATA_DESCRIPTOR* pPropertyData,
                          ULONG BufferSize,
                          BYTE* pBuffer)
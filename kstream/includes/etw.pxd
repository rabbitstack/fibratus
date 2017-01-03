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

from .windows cimport *

cdef extern from "evntcons.h":

    enum: EVENT_HEADER_FLAG_32_BIT_HEADER
    enum: PROCESS_TRACE_MODE_EVENT_RECORD

    ctypedef struct EVENT_TRACE_PROPERTIES:
        pass
    ctypedef struct ETW_BUFFER_CONTEXT:
        UCHAR cpuid "ProcessorNumber"
        UCHAR  Alignment
        USHORT LoggerId

    ctypedef struct EVENT_DESCRIPTOR:
        USHORT Id
        UCHAR Version
        UCHAR Channel
        UCHAR Level
        UCHAR opcode "Opcode"
        USHORT Task
        ULONGLONG Keyword

    ctypedef struct EVENT_HEADER:
        USHORT Size
        USHORT HeaderType
        USHORT flags "Flags"
        USHORT EventProperty
        ULONG thread_id "ThreadId"
        ULONG process_id "ProcessId"
        LARGE_INTEGER timestamp "TimeStamp"
        GUID ProviderId
        EVENT_DESCRIPTOR descriptor "EventDescriptor"
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
        EVENT_HEADER header "EventHeader"
        ETW_BUFFER_CONTEXT buffer_ctx "BufferContext"
        USHORT ExtendedDataCount
        USHORT UserDataLength
        EVENT_HEADER_EXTENDED_DATA_ITEM* ExtendedData
        PVOID UserData
        PVOID user_ctx "UserContext"

cdef extern from "evntrace.h":

    ctypedef VOID (__stdcall *PEVENT_RECORD_CALLBACK) (EVENT_RECORD* e)

    ctypedef ULONG64 TRACEHANDLE

    enum: INVALID_PROCESSTRACE_HANDLE
    enum: EVENT_TRACE_REAL_TIME_MODE

    ctypedef struct EVENT_TRACE_LOGFILE:
        LPTSTR LogFileName
        LPSTR logger_name "LoggerName"
        ULONG LogFileMode
        ULONG trace_mode "ProcessTraceMode"
        PEVENT_RECORD_CALLBACK callback "EventRecordCallback"
        PVOID context "Context"

    TRACEHANDLE open_trace "OpenTrace"(EVENT_TRACE_LOGFILE* logfile)

    ULONG close_trace "CloseTrace"(TRACEHANDLE handle)

    ULONG process_trace "ProcessTrace"(TRACEHANDLE* handle, ULONG count,
                                       FILETIME* start,
                                       FILETIME* end)
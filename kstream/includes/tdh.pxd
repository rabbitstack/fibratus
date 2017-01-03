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

from .windows cimport ULONG
from .etw cimport *

cdef extern from "tdh.h":

    ctypedef ULONG TDHAPI

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
        USHORT in_type "InType"
        USHORT out_type "OutType"

    ctypedef struct EVENT_PROPERTY_INFO:
        ULONG name_offset "NameOffset"
        NON_STRUCT_TYPE non_struct_type "nonStructType"

    ctypedef struct TRACE_PROVIDER_INFO:
        GUID ProviderGuid
        USHORT PropertyCount


    ctypedef struct TDH_CONTEXT:
        pass

    ctypedef struct PROPERTY_DATA_DESCRIPTOR:
        ULONGLONG property_name "PropertyName"
        ULONG     array_index "ArrayIndex"
        ULONG     reserved "Reserved"


    ctypedef struct TRACE_EVENT_INFO:
        GUID ProviderGuid
        GUID event_guid "EventGuid"
        ULONG ProviderNameOffset
        ULONG OpcodeNameOffset
        ULONG PropertyCount
        ULONG property_count "TopLevelPropertyCount"
        EVENT_PROPERTY_INFO properties "EventPropertyInfoArray"[1]


    TDHAPI tdh_get_event_information "TdhGetEventInformation"(EVENT_RECORD* e, ULONG cc,
                                                              TDH_CONTEXT* ctx,
                                                              TRACE_EVENT_INFO* buf,
                                                              ULONG* buf_size) nogil

    ULONG  tdh_get_property_size "TdhGetPropertySize"(EVENT_RECORD* e, ULONG cc,
                                                      TDH_CONTEXT* ctx,
                                                      ULONG count,
                                                      PROPERTY_DATA_DESCRIPTOR* descriptor,
                                                      ULONG *size) nogil

    ULONG  tdh_get_property "TdhGetProperty"(EVENT_RECORD* e, ULONG cc,
                                             TDH_CONTEXT* ctx,
                                             ULONG count,
                                             PROPERTY_DATA_DESCRIPTOR* descriptor,
                                             ULONG buf_size,
                                             BYTE* buf) nogil

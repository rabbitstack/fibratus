# Copyright 2015 by Nedim Sabic (RabbitStack)
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
from _ctypes import Structure, POINTER
from ctypes import c_uint64, c_ulong, c_long, c_ulonglong, c_wchar_p, c_ubyte
from ctypes.wintypes import LARGE_INTEGER, HANDLE

from fibratus.apidefs.guiddef import GUID
import fibratus.ctypes_declarer as declarer


TRACEHANDLE = c_uint64

WNODE_FLAG_TRACED_GUID = 0x00020000
PROCESS_TRACE_MODE_REAL_TIME = 0x00000100


KERNEL_TRACE_CONTROL_GUID = GUID('{9e814aad-3204-11d2-9a82-006008a86939}')
KERNEL_LOGGER_NAME = "NT Kernel Logger"


# enable flags for kernel events
EVENT_TRACE_FLAG_PROCESS = 0x00000001
EVENT_TRACE_FLAG_THREAD = 0x00000002
EVENT_TRACE_FLAG_IMAGE_LOAD = 0x00000004

EVENT_TRACE_FLAG_DISK_IO = 0x00000100
EVENT_TRACE_FLAG_DISK_FILE_IO = 0x00000200

EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS = 0x00001000
EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS = 0x00002000

EVENT_TRACE_FLAG_NETWORK_TCPIP = 0x00010000

EVENT_TRACE_FLAG_REGISTRY = 0x00020000
EVENT_TRACE_FLAG_DBGPRINT = 0x00040000

EVENT_TRACE_FLAG_PROCESS_COUNTERS = 0x00000008
EVENT_TRACE_FLAG_CSWITCH = 0x00000010
EVENT_TRACE_FLAG_DPC = 0x00000020
EVENT_TRACE_FLAG_INTERRUPT = 0x00000040
EVENT_TRACE_FLAG_SYSTEMCALL = 0x00000080

EVENT_TRACE_FLAG_DISK_IO_INIT = 0x00000400

EVENT_TRACE_FLAG_ALPC = 0x00100000
EVENT_TRACE_FLAG_SPLIT_IO = 0x00200000

EVENT_TRACE_FLAG_DRIVER = 0x00800000
EVENT_TRACE_FLAG_PROFILE = 0x01000000
EVENT_TRACE_FLAG_FILE_IO = 0x02000000
EVENT_TRACE_FLAG_FILE_IO_INIT = 0x04000000


EVENT_TRACE_FLAG_DISPATCHER = 0x00000800
EVENT_TRACE_FLAG_VIRTUAL_ALLOC = 0x00004000


EVENT_TRACE_CONTROL_QUERY = 0
EVENT_TRACE_CONTROL_STOP = 1
EVENT_TRACE_CONTROL_UPDATE = 2


EVENT_CONTROL_CODE_DISABLE_PROVIDER = 0
EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
EVENT_CONTROL_CODE_CAPTURE_STATE = 2


class WNODE_HEADER(Structure):
  _fields_ = [('buffer_size', c_ulong),
              ('provider_id', c_ulong),
              ('historical_context', c_uint64),
              ('timestamp', LARGE_INTEGER),
              ('guid', GUID),
              ('client_context', c_ulong),
              ('flags', c_ulong)]


class EVENT_TRACE_PROPERTIES(Structure):
  _fields_ = [('wnode', WNODE_HEADER),
              ('buffer_size', c_ulong),
              ('minimum_buffers', c_ulong),
              ('maximum_buffers', c_ulong),
              ('maximum_file_size', c_ulong),
              ('log_file_mode', c_ulong),
              ('flush_timer', c_ulong),
              ('enable_flags', c_ulong),
              ('age_limit', c_long),
              ('number_of_buffers', c_ulong),
              ('free_buffers', c_ulong),
              ('events_lost', c_ulong),
              ('buffers_written', c_ulong),
              ('log_buffers_lost', c_ulong),
              ('real_time_buffer_lost', c_ulong),
              ('logger_thread_id', HANDLE),
              ('log_file_name_offset', c_ulong),
              ('logger_name_offset', c_ulong)]


class TRACE_GUID_REGISTRATION(Structure):
  _fields_ = [('guid', POINTER(GUID)),
               ('reg_handle', HANDLE)]


class EVENT_FILTER_DESCRIPTOR(Structure):
    _fields_ = [('Ptr', c_ulonglong),
                ('Size', c_ulong),
                ('Type', c_ulong)]


class ENABLE_TRACE_PARAMETERS(Structure):
    _fields_ = [('Version', c_ulong),
                ('EnableProperty', c_ulong),
                ('ControlFlags', c_ulong),
                ('SourceId', GUID),
                ('EnableFilterDesc', POINTER(EVENT_FILTER_DESCRIPTOR)),
                ('FilterDescCount', c_ulong)]


start_trace = declarer.declare(declarer.ADVAPI, 'StartTraceW',
                               [POINTER(TRACEHANDLE), c_wchar_p, POINTER(EVENT_TRACE_PROPERTIES)],
                               c_ulong)


control_trace = declarer.declare(declarer.ADVAPI, 'ControlTraceW',
                                 [TRACEHANDLE, c_wchar_p, POINTER(EVENT_TRACE_PROPERTIES), c_ulong],
                                 c_ulong)

enable_trace_ex = declarer.declare(declarer.ADVAPI, 'EnableTraceEx2',
                                   [TRACEHANDLE, POINTER(GUID), c_ulong, c_ubyte, c_ulonglong,
                                    c_ulonglong, c_ulong, POINTER(ENABLE_TRACE_PARAMETERS)],
                                   c_ulong)
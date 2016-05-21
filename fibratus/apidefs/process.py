# Copyright 2015 by Nedim Sabic (RabbitStack)
# All Rights Reserved.
# http://rabbitstack.github.io

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
from _ctypes import POINTER
from ctypes.wintypes import DWORD, BOOL, HANDLE, ULONG, PULONG, BYTE, PDWORD

from fibratus.apidefs.cdefs import *
from fibratus.apidefs.sys import malloc, free
import fibratus.ctypes_declarer as declarer


# process access rights
PROCESS_VM_READ = 0x0010
PROCESS_DUP_HANDLE = 0x0040
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

# thread access rights
THREAD_QUERY_INFORMATION = 0x0040

# ZwQueryInformationProcess constants
PROCESS_BASIC_INFO = 0
PROCESS_IMAGE_FILENAME = 27


# PEB (Process Environment Block) structures
class LIST_ENTRY(Structure):
    pass
LIST_ENTRY._fields_ = [('flink', POINTER(LIST_ENTRY)), ('blink', POINTER(LIST_ENTRY))]


class PEB_LDR_DATA(Structure):
    _fields_ = [('reserved1', BYTE * 8),
                ('reserved2', BYTE * 3),
                ('in_memory_order_module_list', LIST_ENTRY)]


class RTL_USER_PROCESS_PARAMETERS(Structure):
    _fields_ = [('reserved1', BYTE * 16),
                ('reserved2', PVOID * 10),
                ('image_path_name', UNICODE_STRING),
                ('command_line', UNICODE_STRING)]


class PEB(Structure):
    _fields_ = [('reserved1', BYTE * 2),
                ('being_debugged', BYTE),
                ('reserved2', BYTE * 21),
                ('ldr', POINTER(PEB_LDR_DATA)),
                ('process_parameters', POINTER(RTL_USER_PROCESS_PARAMETERS)),
                ('reserved3', BYTE * 520),
                ('post_process_init_routine', PVOID),
                ('reserved4', BYTE * 136),
                ('session_id', ULONG)]


class PROCESS_BASIC_INFORMATION(Structure):
    _fields_ = [('reserved1', PVOID),
                ('peb_base_address', POINTER(PEB)),
                ('reserved2', PVOID * 2),
                ('unique_process_id', PULONG),
                ('inherited_from_unique_process_id', ULONG)]

open_process = declarer.declare(declarer.KERNEL, 'OpenProcess',
                                [DWORD, BOOL, DWORD],
                                HANDLE)

open_thread = declarer.declare(declarer.KERNEL, 'OpenThread',
                               [DWORD, BOOL, DWORD],
                               HANDLE)

_read_process_memory = declarer.declare(declarer.KERNEL, 'ReadProcessMemory',
                                        [HANDLE, LPVOID, LPVOID, SIZE_T, POINTER(SIZE_T)],
                                        BOOL)

zw_query_information_process = declarer.declare(declarer.NT, 'ZwQueryInformationProcess',
                                                [HANDLE, DWORD, PVOID, ULONG, PULONG],
                                                DWORD)
query_full_process_image_name = declarer.declare(declarer.KERNEL, 'QueryFullProcessImageNameW',
                                                 [HANDLE, DWORD, LPTSTR, PDWORD],
                                                 BOOL)

get_current_process = declarer.declare(declarer.KERNEL, 'GetCurrentProcess',
                                       [],
                                       HANDLE)
get_process_id_of_thread = declarer.declare(declarer.KERNEL, 'GetProcessIdOfThread',
                                            [HANDLE],
                                            DWORD)


def read_process_memory(process, chunk, size):
    """Reads a memory block from the process address space.
    """
    buff = malloc(size)
    status = _read_process_memory(process,
                                  chunk,
                                  buff,
                                  size,
                                  None)
    if status != ERROR_SUCCESS:
        return buff
    else:
        free(buff)

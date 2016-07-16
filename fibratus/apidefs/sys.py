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
from ctypes import c_int, c_byte, WINFUNCTYPE
from ctypes.wintypes import DWORD, ULONG, PULONG, USHORT, HANDLE, BOOL, SHORT, WCHAR, CHAR, WORD, LPDWORD

from fibratus.apidefs.cdefs import *
import fibratus.ctypes_declarer as declarer


SYSTEM_HANDLE_INFORMATION_CLASS = 16

PUBLIC_OBJECT_BASIC_INFORMATION = 0
PUBLIC_OBJECT_NAME_INFORMATION = 1
PUBLIC_OBJECT_TYPE_INFORMATION = 2

# this constants may vary from
# one Windows version to another
# for Win 7/8 they should have
# the following values
FILE_OBJECT_TYPE_INDEX = 28


STD_OUTPUT_HANDLE = -11
INVALID_HANDLE_VALUE = -1

CONSOLE_TEXTMODE_BUFFER = 1

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000

FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002


# console structures
class CURSOR_INFO(ctypes.Structure):
    _fields_ = [("size", c_int),
                ("visible", c_byte)]


class COORD(ctypes.Structure):
    _fields_ = [("x", SHORT), ("y", SHORT)]


class SMALL_RECT(ctypes.Structure):
    _fields_ = [("left", SHORT),
                ("top", SHORT),
                ("right", SHORT),
                ("bottom", SHORT)]


class CHAR_INFOU(ctypes.Union):
    _fields_ = [("unicode_char", WCHAR), ("ascii_char", CHAR)]


class CHAR_INFO(ctypes.Structure):
    _anonymous_ = ("char",)
    _fields_ = [("char", CHAR_INFOU), ("attributes", WORD)]


class CONSOLE_SCREEN_BUFFER_INFO(ctypes.Structure):
    _fields_ = [('size', COORD),
                ('cursor_position', COORD),
                ('attributes', WORD),
                ('window', SMALL_RECT),
                ('maximum_window_size', COORD)]


class SYSTEM_HANDLE(Structure):
    _fields_ = [('process_id', ULONG),
                ('object_type_number', UCHAR),
                ('flags', UCHAR),
                ('handle', USHORT),
                ('object', PVOID),
                ('access_mask', DWORD)]


class SYSTEM_HANDLE_INFORMATION(Structure):
    _fields_ = [('number_of_handles', ULONG),
                ('handles', SYSTEM_HANDLE * 1)]


class OBJECT_TYPE_INFORMATION(Structure):
    _fields_ = [('type_name', UNICODE_STRING),
                ('reserved', ULONG * 22)]


# retrieves the specified system information
zw_query_system_information = declarer.declare(declarer.NT, 'ZwQuerySystemInformation',
                                               [DWORD, PVOID, ULONG, PULONG],
                                               DWORD)

# memory alloc/free functions
malloc = declarer.declare(declarer.C, 'malloc', [c_size_t], c_void_p)
realloc = declarer.declare(declarer.C, 'realloc', [c_void_p, c_size_t], c_void_p)
free = declarer.declare(declarer.C, 'free', [c_void_p], None)

# object handle cleanup
close_handle = declarer.declare(declarer.KERNEL, 'CloseHandle', [HANDLE], BOOL)
# duplicate object handle
duplicate_handle = declarer.declare(declarer.KERNEL, 'DuplicateHandle',
                                    [HANDLE, HANDLE, HANDLE, POINTER(HANDLE), DWORD, ULONG, ULONG],
                                    DWORD)

# query object name / type
nt_query_object = declarer.declare(declarer.NT, 'NtQueryObject',
                                   [HANDLE, ULONG, PVOID, ULONG, PULONG],
                                   DWORD)

# low level console api
get_std_handle = declarer.declare(declarer.KERNEL, 'GetStdHandle', [DWORD], HANDLE)
set_console_active_screen_buffer = declarer.declare(declarer.KERNEL, 'SetConsoleActiveScreenBuffer', [HANDLE], BOOL)

create_console_screen_buffer = declarer.declare(declarer.KERNEL, 'CreateConsoleScreenBuffer',
                                                [DWORD, DWORD, c_void_p, DWORD, LPVOID], HANDLE)
get_console_screen_buffer_info = declarer.declare(declarer.KERNEL, 'GetConsoleScreenBufferInfo',
                                                  [HANDLE, POINTER(CONSOLE_SCREEN_BUFFER_INFO)], BOOL)

write_console_output = declarer.declare(declarer.KERNEL, 'WriteConsoleOutputW',
                                        [HANDLE, POINTER(CHAR_INFO), COORD, COORD, POINTER(SMALL_RECT)], BOOL)

set_console_cursor_position = declarer.declare(declarer.KERNEL, 'SetConsoleCursorPosition',
                                               [HANDLE, COORD], BOOL)

get_console_cursor_info = declarer.declare(declarer.KERNEL, 'GetConsoleCursorInfo',
                                           [HANDLE, POINTER(CURSOR_INFO)], BOOL)

set_console_cursor_info = declarer.declare(declarer.KERNEL, 'SetConsoleCursorInfo',
                                           [HANDLE, POINTER(CURSOR_INFO)], BOOL)

write_console_unicode = declarer.declare(declarer.KERNEL, 'WriteConsoleW',
                                         [HANDLE, c_void_p, DWORD, LPDWORD, LPVOID], BOOL)


PHANDLER_ROUTINE = WINFUNCTYPE(BOOL, DWORD)
set_console_ctrl_handler = declarer.declare(declarer.KERNEL, 'SetConsoleCtrlHandler',
                                            [PHANDLER_ROUTINE, BOOL], BOOL)


# event objects
create_event = declarer.declare(declarer.KERNEL, 'CreateEventW', [c_void_p, BOOL, BOOL, LPTSTR], HANDLE)



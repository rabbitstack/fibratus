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
from ctypes import Structure
from ctypes import c_void_p, c_ubyte, c_ushort, c_ulong, c_size_t, c_wchar_p
import re
import ctypes

# undefined ctypes wintypes
LPVOID = c_void_p
PVOID = c_void_p
UCHAR = c_ubyte
SIZE_T = c_size_t
LPTSTR = c_wchar_p

# status codes
STATUS_INFO_LENGTH_MISMATCH = 0xc0000004
STATUS_SUCCESS = 0

# error codes
ERROR_SUCCESS = 0x0
ERROR_ACCESS_DENIED = 0x5
ERROR_BAD_LENGTH = 0x18
ERROR_INVALID_PARAMETER = 0x57
ERROR_ALREADY_EXISTS = 0xB7


def get_last_error():
    return ctypes.GetLastError()


class UNICODE_STRING(Structure):
    _fields_ = [('length', c_ushort),
                ('maximum_length', c_ushort),
                ('buffer', c_void_p)]


class GUID(Structure):
    _fields_ = [("Data1", c_ulong),
                ("Data2", c_ushort),
                ("Data3", c_ushort),
                ("Data4", c_ubyte * 8)]
    _GUID_REGEX = re.compile('{([0-9A-F]{8})-([0-9A-F]{4})-([0-9A-F]{4})-([0-9A-F]{2})([0-9A-F]{2})-'
                             '([0-9A-F]{2})([0-9A-F]{2})([0-9A-F]{2})'
                             '([0-9A-F]{2})([0-9A-F]{2})([0-9A-F]{2})}', re.I)

    def __init__(self, gs=None):
        if gs:
            match = self._GUID_REGEX.match(gs)
            g = [int(i, 16) for i in match.groups()]
            self.Data1 = g[0]
            self.Data2 = g[1]
            self.Data3 = g[2]
            for i in range(8):
                self.Data4[i] = g[3 + i]

    def __str__(self):
        return "{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}" % \
               (self.Data1, self.Data2, self.Data3,
                self.Data4[0], self.Data4[1],
                self.Data4[2], self.Data4[3], self.Data4[4],
                self.Data4[5], self.Data4[6], self.Data4[7])

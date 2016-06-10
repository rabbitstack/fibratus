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
import ctypes
import re


class GUID(ctypes.Structure):
    _DECOMPOSE_RE = re.compile('{([0-9A-F]{8})-([0-9A-F]{4})-([0-9A-F]{4})-([0-9A-F]{2})([0-9A-F]{2})-'
                               '([0-9A-F]{2})([0-9A-F]{2})([0-9A-F]{2})'
                               '([0-9A-F]{2})([0-9A-F]{2})([0-9A-F]{2})}', re.I)

    def __init__(self, guid_as_str=None):
        if guid_as_str:
            m = self._DECOMPOSE_RE.match(guid_as_str)
            g = [int(i, 16) for i in m.groups()]
            self.Data1 = g[0]
            self.Data2 = g[1]
            self.Data3 = g[2]
            for i in range(8):
                self.Data4[i] = g[3 + i]

    _fields_ = [("Data1", ctypes.c_ulong),
                ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort),
                ("Data4", ctypes.c_ubyte * 8)]

    def __str__(self):
        return "{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}" % \
               (self.Data1, self.Data2, self.Data3,
                self.Data4[0], self.Data4[1],
                self.Data4[2], self.Data4[3], self.Data4[4],
                self.Data4[5], self.Data4[6], self.Data4[7])

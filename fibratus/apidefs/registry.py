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
from ctypes.wintypes import HKEY, DWORD, LPDWORD, LONG, LPCWSTR
from enum import Enum

from fibratus.apidefs.cdefs import *
import fibratus.ctypes_declarer as declarer


# query type flags
RRF_RT_ANY = 0x0000ffff

# reserved key handles
HKEY_CLASSES_ROOT = HKEY(0x80000000)
HKEY_CURRENT_USER = HKEY(0x80000001)
HKEY_LOCAL_MACHINE = HKEY(0x80000002)
HKEY_USERS = HKEY(0x80000003)

MAX_BUFFER_SIZE = 4096
reg_get_value = declarer.declare(declarer.ADVAPI, 'RegGetValueW',
                                 [HKEY, LPCWSTR, LPCWSTR,
                                 DWORD, LPDWORD, PVOID, LPDWORD],
                                 LONG)


class ValueType(Enum):
    REG_NONE = 0
    REG_SZ = 1
    REG_EXPAND_SZ = 2
    REG_BINARY = 3
    REG_DWORD = 4
    REG_DWORD_BIG_ENDIAN = 5
    REG_LINK = 6
    REG_MULTI_SZ = 7
    REG_RESOURCE_LIST = 8
    REG_FULL_RESOURCE_DESCRIPTOR = 9
    REG_RESOURCE_REQUIREMENTS_LIST = 10
    REG_QWORD = 11

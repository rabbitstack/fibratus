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
from ctypes.wintypes import HANDLE, DWORD, BOOL, WCHAR, LONG

import fibratus.ctypes_declarer as declarer
from fibratus.apidefs.cdefs import LPVOID, LPTSTR


FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004

# if the file already exists, replace it with the given file. If it does not, create the given file.
FILE_SUPERSEDE = 0x00000000
# if the file already exists, open it instead of creating a new file.
# If it does not, fail the request and do not create a new file.
FILE_OPEN = 0x00000001
# if the file already exists, fail the request and do not create or open the given file.
# If it does not, create the given file.
FILE_CREATE = 0x00000002
# If the file already exists, open it. If it does not, create the given file.
FILE_OPEN_IF = 0x00000003
# If the file already exists, open it and overwrite it. If it does not, fail the request.
FILE_OVERWRITE = 0x00000004
# If the file already exists, open it and overwrite it. If it does not, create the given file.
FILE_OVERWRITE_IF = 0x00000005

# the file being created or opened is a directory file
FILE_DIRECTORY_FILE = 0x00000001
# open a file with a reparse point and bypass normal reparse point processing for the file
FILE_OPEN_REPARSE_POINT = 0x00200000


class FILE_NAME_INFO(Structure):
    _fields_ = [('file_name_length', DWORD),
                ('filename', WCHAR * 1)]


get_file_info_by_handle = declarer.declare(declarer.KERNEL, 'GetFileInformationByHandleEx',
                                           [HANDLE, DWORD, LPVOID, DWORD],
                                           BOOL)
query_dos_device = declarer.declare(declarer.KERNEL, 'QueryDosDeviceW',
                                    [LPTSTR, LPTSTR, DWORD],
                                    DWORD)

_get_osfhandle = declarer.declare(declarer.C, '_get_osfhandle',
                                  [DWORD],
                                  LONG)

get_file_type = declarer.declare(declarer.KERNEL, 'GetFileType',
                                 [HANDLE],
                                 DWORD)
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
from _ctypes import POINTER, byref, addressof
from ctypes import cast, c_ulong, c_wchar_p
from ctypes.wintypes import HANDLE, ULONG
from enum import Enum

from fibratus.common import DotD as ddict
from fibratus.apidefs.cdefs import STATUS_INFO_LENGTH_MISMATCH, STATUS_SUCCESS, ERROR_SUCCESS, \
    UNICODE_STRING
from fibratus.apidefs.process import open_process, PROCESS_DUP_HANDLE, get_current_process
from fibratus.apidefs.registry import MAX_BUFFER_SIZE
from fibratus.apidefs.sys import zw_query_system_information, SYSTEM_HANDLE_INFORMATION_CLASS, \
    SYSTEM_HANDLE_INFORMATION, free, realloc, SYSTEM_HANDLE, malloc, duplicate_handle, nt_query_object, \
    PUBLIC_OBJECT_TYPE_INFORMATION, OBJECT_TYPE_INFORMATION, PUBLIC_OBJECT_NAME_INFORMATION, close_handle
from fibratus.errors import HandleEnumError


class HandleType(Enum):
    FILE = 0
    DIRECTORY = 1
    KEY = 2
    ALPC_PORT = 3
    SECTION = 4
    MUTANT = 5
    EVENT = 6
    DESKTOP = 7
    SEMAPHORE = 8
    TIMER = 9
    TOKEN = 10
    JOB = 11


class HandleRepository(object):
    """Stores open handle objects.
    """

    def __init__(self):
        self._object_buff_size = 0x1000
        self._object_types = {}
        # the object handles with these
        # masks shouldn't be queried,
        # otherwise the call could hang
        # the main thread
        self._nasty_access_masks = [0x120189,
                                    0x0012019f,
                                    0x1A019F]

        self._handle_types = [name for name, _ in HandleType.__members__.items()]
        self._buffers = []

    def query_handles(self, pid=None):
        raw_handles = self._enum_handles(pid)
        current_ps = HANDLE(get_current_process())
        handles = []
        # find the object handles for the process
        for _, handle in raw_handles.items():
            ps_handle = open_process(PROCESS_DUP_HANDLE,
                                     False,
                                     handle.pid)
            if ps_handle:
                handle_copy = HANDLE()
                # to query the object handle
                # we need to duplicate it in
                # the address space of the current process
                status = duplicate_handle(ps_handle,
                                          handle.handle,
                                          current_ps,
                                          byref(handle_copy),
                                          0, 0, 0)
                if status != ERROR_SUCCESS:
                    # get the object type
                    handle_type = self._query_handle(handle_copy,
                                                     PUBLIC_OBJECT_TYPE_INFORMATION,
                                                     OBJECT_TYPE_INFORMATION)
                    if handle_type:
                        handle_type = cast(handle_type.contents.type_name.buffer, c_wchar_p) \
                            .value \
                            .upper().replace(' ', '_')
                        # query for object name
                        # (file names, registry keys,
                        # sections, ALPC ports, etc)
                        # check the access mask to make
                        # sure `NtQueryObject` won't hang
                        if handle_type in self._handle_types and \
                                handle.access_mask not in self._nasty_access_masks:
                            handle_name = self._query_handle(handle_copy,
                                                             PUBLIC_OBJECT_NAME_INFORMATION,
                                                             UNICODE_STRING)
                            if handle_name:
                                handle_name = cast(handle_name.contents.buffer, c_wchar_p).value
                            handle_info = HandleInfo(handle.handle,
                                                     handle.obj,
                                                     HandleType(HandleType.__getattr__(handle_type)),
                                                     handle_name,
                                                     handle.pid)
                            handles.append(handle_info)

                    close_handle(handle_copy)
                close_handle(ps_handle)
        return handles

    def free_buffers(self):
        for buff in self._buffers:
            free(buff)

    def _enum_handles(self, process_id=None):
        """Enumerates handle information.

        Enumerates handle info on
        the start of the kernel capture.

        Returns a dictionary of handle's
        information including the handle id,
        access mask, and the process which owns
        the handle.
        """
        buff_size = MAX_BUFFER_SIZE
        size = c_ulong()
        # allocate the initial buffer
        buff = malloc(buff_size)
        handles = {}

        while True:
            status = zw_query_system_information(SYSTEM_HANDLE_INFORMATION_CLASS,
                                                 buff,
                                                 buff_size,
                                                 byref(size))
            if status == STATUS_INFO_LENGTH_MISMATCH:
                # the buffer is too small
                # increment the buffer size and try again
                buff_size += MAX_BUFFER_SIZE
            elif status == STATUS_SUCCESS:
                # cast the buffer to `SYSTEM_HANDLE_INFORMATION` struct
                # which contains an array of `SYSTEM_HANDLE` structures
                sys_handle_info = cast(buff, POINTER(SYSTEM_HANDLE_INFORMATION))
                sys_handle_info = sys_handle_info.contents
                handle_count = sys_handle_info.number_of_handles

                # resize the array size to the
                # actual number of file handles
                sys_handles = (SYSTEM_HANDLE * buff_size).from_address(addressof(sys_handle_info.handles))

                for i in range(handle_count):
                    sys_handle = sys_handles[i]
                    pid = sys_handle.process_id
                    handle = sys_handle.handle
                    obj = sys_handle.object
                    obj_type_index = sys_handle.object_type_number
                    access_mask = sys_handle.access_mask
                    if process_id and process_id == pid:
                        handles[obj] = ddict(pid=process_id,
                                             handle=handle,
                                             obj=obj,
                                             access_mask=access_mask,
                                             obj_type_index=obj_type_index)
                    elif process_id is None:
                        handles[obj] = ddict(pid=pid,
                                             handle=handle,
                                             obj=obj,
                                             access_mask=access_mask,
                                             obj_type_index=obj_type_index)
                break
            else:
                raise HandleEnumError(status)
            # reallocate the buffer
            buff = realloc(buff, buff_size)
        # free the buffer memory
        free(buff)

        return handles

    def _async_query_object(self):
        pass

    def _query_handle(self, handle, klass, object_info_type):
        """Gets the object handle info.

        Parameters
        ----------


        handle: HANDLE
            handle object
        klass: int
            the class of information to query
        object_info_type: Structure
            structure type which holds the handle info
        """
        buff = malloc(self._object_buff_size)
        rlen = ULONG()
        status = nt_query_object(handle,
                                 klass,
                                 buff,
                                 self._object_buff_size,
                                 byref(rlen))
        if status >= 0:
            info = cast(buff, POINTER(object_info_type))
            self._buffers.append(buff)
            return info
        else:
            # reallocate the buffer size
            # and try again
            buff = realloc(buff, rlen.value)
            status = nt_query_object(handle,
                                     klass,
                                     buff,
                                     self._object_buff_size,
                                     None)
            if status >= 0:
                info = cast(buff, POINTER(object_info_type))
                self._buffers.append(buff)
                return info
            else:
                free(buff)
                return None


class HandleInfo():
    """Saves the handle meta data.
    """

    def __init__(self, handle, obj, handle_type, name, pid):
        self._handle = handle
        self._obj = obj
        self._handle_type = handle_type
        self._name = name
        self._pid = pid

    @property
    def name(self):
        return self._name

    @property
    def handle_type(self):
        return self._handle_type

    @property
    def obj(self):
        return self._obj

    @property
    def pid(self):
        return self._pid

    @property
    def handle(self):
        return self._handle

    def __str__(self):
        return '%s type: [%s] object address: [%s] handle id: [%s] pid: [%s]' % \
               (self._name, self._handle_type,
                hex(self._obj),
                self._handle,
                self._pid)

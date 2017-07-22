# Copyright 2017 by Nedim Sabic (RabbitStack)
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

from kstream.includes.windows cimport UCHAR, ULONG, wchar_t, get_process_id_of_thread, open_thread, close_handle, \
    THREAD_QUERY_LIMITED_INFORMATION, HANDLE
from libcpp.unordered_map cimport unordered_map
from cython.operator cimport dereference as deref

cdef enum:
    INVALID_PID = 4294967295

cdef struct PROCESS_INFO:
    # process identifier
    ULONG pid
    # process parent identifier
    ULONG ppid
    # name of the image file
    wchar_t* name

cdef struct THREAD_INFO:
    # thread identifier
    ULONG tid
    # process identifier
    ULONG pid

cdef inline ULONG pid_from_tid(ULONG tid, unordered_map[ULONG, THREAD_INFO]* thread_map) nogil:
    cdef unordered_map[ULONG, THREAD_INFO].iterator thread_iter = thread_map.find(tid)
    # try to resolve pid from tid by
    # querying the thread map
    if thread_iter != thread_map.end():
        ti = deref(thread_iter).second
        return ti.pid
    else:
        # if not found, try to resolve via
        # `GetProcessIdOfThread` Windows API function
        thread = open_thread(THREAD_QUERY_LIMITED_INFORMATION,
                             False,
                             tid)
        if thread != NULL:
            pid = get_process_id_of_thread(thread)
            close_handle(thread)
            return pid
        else:
            return INVALID_PID

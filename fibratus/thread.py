# Copyright 2015 by Nedim Sabic (RabbitStack)
# All Rights Reserved.
# http://rabbitstack.github.io
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

from _ctypes import sizeof
from ctypes import byref, cast
from ctypes.wintypes import MAX_PATH
import os

from fibratus.kevent_types import CREATE_PROCESS, ENUM_PROCESS, TERMINATE_THREAD, TERMINATE_PROCESS, \
    CREATE_THREAD, ENUM_THREAD
from fibratus.apidefs.process import *
from fibratus.apidefs.cdefs import STATUS_SUCCESS
from fibratus.apidefs.sys import close_handle, malloc, free
from fibratus.common import DotD as ddict, NA


class ThreadRegistry(object):

    def __init__(self, handle_repository, handles):
        self._threads = {}
        self.on_thread_added_callback = None
        self.handle_repository = handle_repository
        self._handles = handles

    def add_thread(self, ketype, kti):
        """Adds a new process or thread to thread registry.

        Parameters
        ----------

        ketype: tuple
            kernel event type
        kti: dict
            event payload as coming from the
            kernel event stream collector
        """
        if ketype == CREATE_PROCESS or ketype == ENUM_PROCESS:
            parent_pid = int(kti.parent_id, 16)
            process_id = int(kti.process_id, 16)
            # we assume the process id is
            # equal to thread id (in a single
            # threaded process)
            thread_id = process_id
            name = kti.image_file_name
            comm = kti.command_line
            suid = kti.user_sid

            thread = ThreadInfo(process_id, thread_id,
                                parent_pid,
                                name,
                                comm,
                                suid)
            if ketype == ENUM_PROCESS:
                thread.handles = [handle for handle in self._handles if handle.pid == process_id]
            else:
                thread.handles = self.handle_repository.query_handles(process_id)
            self._threads[process_id] = thread
        elif ketype == CREATE_THREAD or ketype == ENUM_THREAD:
            # new thread created in the
            # context of the existing process
            # `procces_id` is the parent
            # of this thread
            process_id = int(kti.process_id, 16)
            parent_pid = process_id
            thread_id = int(kti.t_thread_id, 16)

            if parent_pid in self._threads:
                # copy info from the process
                # which created this thread
                pthread = self._threads[parent_pid]
                # increment the number of threads
                # for this process
                pthread.increment_child_count()

                name = pthread.name
                comm = pthread.comm
                suid = pthread.suid

                thread = ThreadInfo(process_id, thread_id,
                                    parent_pid,
                                    name,
                                    comm,
                                    suid)
                thread.ustack_base = hex(kti.user_stack_base)
                thread.kstack_base = hex(kti.stack_base)
                thread.base_priority = kti.base_priority
                thread.io_priority = kti.io_priority
                self._threads[thread_id] = thread
            else:
                # the parent process has not been found
                # query the os for process information
                handle = open_process(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                                      False,
                                      parent_pid)
                info = {}
                if handle:
                    info = self._query_process_info(handle)
                    close_handle(handle)
                else:
                    if get_last_error() == ERROR_ACCESS_DENIED:
                        if parent_pid == 0:
                            info = ddict(name='idle',
                                         comm='idle',
                                         parent_id=0)
                        else:
                            # the access to protected / system process
                            # can't be done with PROCESS_VM_READ or PROCESS_QUERY_INFORMATION
                            # flags. Open the process again but with
                            # restricted access rights, so we can get the process image file name
                            handle = open_process(PROCESS_QUERY_LIMITED_INFORMATION,
                                                  False,
                                                  parent_pid)
                            if handle:
                                info = self._query_process_info(handle, False)
                                close_handle(handle)

                # add a new thread and the parent process
                # we just found to avoid continuous lookup
                name = info.name if len(info) > 0 and info.name else NA
                comm = info.comm if len(info) > 0 and info.comm else NA
                ppid = info.parent_pid if len(info) > 0 and info.parent_pid else NA

                thread = ThreadInfo(process_id, thread_id,
                                    process_id,
                                    name,
                                    comm,
                                    None)
                thread.ustack_base = hex(kti.user_stack_base)
                thread.kstack_base = hex(kti.stack_base)
                thread.base_priority = kti.base_priority
                thread.io_priority = kti.io_priority

                parent = ThreadInfo(process_id, process_id,
                                    ppid,
                                    name,
                                    comm,
                                    None)
                # enumerate parent handles
                parent.handles = self.handle_repository.query_handles(process_id)

                self._threads[thread_id] = thread
                self._threads[parent_pid] = parent

        if self.on_thread_added_callback and callable(self.on_thread_added_callback):
            self.on_thread_added_callback(thread)

    def remove_thread(self, ketype, kti):
        """Removes the thread or process from the registry.

        Parameters
        ----------

        ketype: tuple
            kernel event type
        kti: dict
            event payload as coming from the
            kernel event stream collector
        """
        if ketype == TERMINATE_THREAD:
            thread_id = int(kti.t_thread_id, 16)
            if thread_id in self._threads:
                # remove the thread and
                # decrement the child count of
                # the parent process
                if self._threads[thread_id].child_count == 0:
                    thread = self._threads.pop(thread_id)
                    if thread and thread.pid in self._threads:
                        parent = self._threads[thread.pid]
                        parent.decrement_child_count()
        elif ketype == TERMINATE_PROCESS:
            # the process has exited
            # remove all of its threads
            process_id = int(kti.process_id, 16)
            if process_id in self._threads:
                proc = self._threads.pop(process_id)
                if proc.child_count > 0:
                    self._threads = dict((k, v) for k, v in self._threads.items()
                                         if v.child_count == 0 and k != process_id)

    def init_thread_kevent(self, kevent, ketype, kti):
        """Initialize kernel event.

        Parameters
        ----------

        kevent: KEvent
            instance of `KEvent` class
        ketype: tuple
            kernel event type
        kti: dict
            kernel event payload
        """
        if ketype == CREATE_THREAD or ketype == TERMINATE_THREAD:
            tid = int(kti.t_thread_id, 16)
            thread = self.get_thread(tid)
            if thread:
                kevent.params = dict(pid=thread.pid,
                                     tid=tid,
                                     kstack_base=hex(kti.stack_base),
                                     ustack_base=hex(kti.user_stack_base),
                                     io_priority=kti.io_priority,
                                     base_priority=kti.base_priority)
                kevent.pid = thread.pid
                kevent.tid = tid
        else:
            pid = int(kti.process_id, 16)
            thread = self.get_thread(pid)
            if thread:
                kevent.params = dict(pid=pid,
                                     name=thread.name,
                                     comm=thread.comm,
                                     exe=thread.exe,
                                     ppid=thread.ppid)
                kevent.pid = thread.ppid

    def set_thread_added_callback(self, callback):
        self.on_thread_added_callback = callback

    def get_thread(self, tid):
        return self._threads[tid] if tid in self._threads else None

    @property
    def threads(self):
        return self._threads

    def _query_process_info(self, handle, read_peb=True):
        """Gets an extended proc info.

        Parameters
        -----------

        handle: HANDLE
            handle to process for which the info
            should be acquired
        read_peb: boolean
            true in case the process PEB should be read

        """
        pbi_buff = malloc(sizeof(PROCESS_BASIC_INFORMATION))
        status = zw_query_information_process(handle,
                                              PROCESS_BASIC_INFO,
                                              pbi_buff,
                                              sizeof(PROCESS_BASIC_INFORMATION),
                                              byref(ULONG()))

        info = {}

        if status == STATUS_SUCCESS:
            pbi = cast(pbi_buff, POINTER(PROCESS_BASIC_INFORMATION))
            ppid = pbi.contents.inherited_from_unique_process_id
            if read_peb:
                # read the PEB to get the process parameters.
                # Because the PEB structure resides
                # in the address space of another process
                # we must read the memory block in order
                # to access the structure's fields
                peb_addr = pbi.contents.peb_base_address
                peb_buff = read_process_memory(handle, peb_addr, sizeof(PEB))
                if peb_buff:
                    peb = cast(peb_buff, POINTER(PEB))
                    # read the RTL_USER_PROCESS_PARAMETERS struct
                    # which contains the command line and the image
                    # name of the process
                    pp = peb.contents.process_parameters
                    pp_buff = read_process_memory(handle,
                                                  pp,
                                                  sizeof(RTL_USER_PROCESS_PARAMETERS))
                    if pp_buff:
                        pp = cast(pp_buff, POINTER(RTL_USER_PROCESS_PARAMETERS))

                        comm = pp.contents.command_line.buffer
                        comm_len = pp.contents.command_line.length
                        exe = pp.contents.image_path_name.buffer
                        exe_len = pp.contents.image_path_name.length

                        # these memory reads are required
                        # to copy the command line and image name buffers
                        cb = read_process_memory(handle, comm, comm_len)
                        eb = read_process_memory(handle, exe, exe_len)

                        if cb and eb:
                            # cast the buffers to
                            # UNICODE strings
                            comm = cast(cb, c_wchar_p).value
                            exe = cast(eb, c_wchar_p).value

                            # the image name contains the full path
                            # split the string to get the exec name
                            name = exe[exe.rfind('\\') + 1:]
                            info = ddict(name=name,
                                         comm=comm,
                                         parent_pid=ppid)
                            free(cb)
                            free(eb)
                        free(pp_buff)

                    free(peb_buff)
            else:
                # query only the process image file name
                exe = ctypes.create_unicode_buffer(MAX_PATH)
                size = DWORD(MAX_PATH)
                name = None
                status = query_full_process_image_name(handle,
                                                       0,
                                                       exe,
                                                       byref(size))
                if status:
                    exe = exe.value
                    name = exe[exe.rfind('\\') + 1:]
                info = ddict(name=name if name else NA,
                             comm=exe,
                             parent_pid=ppid)
        if pbi_buff:
            free(pbi_buff)

        return info


class ThreadInfo(object):
    """Represents the state of thread or process.
    """
    def __init__(self, pid, tid, ppid, name, comm, suid):
        """Creates an instance of `ThreadInfo` class.

        Parameters
        ----------

        pid: int
            process identifier
        tid: int
            thread identifier in the scope of
            an existing process
        ppid: int
            parent process identifier
        name: str
            process name (cmd.exe)
        comm: str
            the full command line of a process
            (C:\Windows\system32\cmd.exe /cdir /-C /W)
        suid: tuple
            the security identifier of the user who
            created the process. It consists of a tuple
            with user name and the domain.


        Attributes
        ----------

        exe: str
            the full name of the executable
            (C:\Windows\system32\cmd.exe)
        args: list
            command line arguments for the process
            (/cdir, /-C, /W)
        child_count: int
            the number of threads for this process
        handles: list
            a list of handles which owns the process
        ustack_base: int
            the base address of the thread user-space stack
        kstack_base: int
            the base address of the thread kernel-space stack
        io_priority: int
            thread I/O priority
        base_priority: int
            thread CPU priority
        """
        self._pid = pid
        self._tid = tid
        self._ppid = ppid

        # get the executable from the
        # full file system path
        head, _ = os.path.split(comm[0:comm.rfind('exe')])
        self._exe = '%s\%s' % (head, name)

        self._name = name.lower() if NA not in name else NA
        self._comm = comm
        # the command line arguments
        # are separated by blank space
        self._args = comm.split()[1:]
        self._suid = suid
        self._child_count = 0
        self._handles = []

        self._ustack_base = 0x0
        self._kstack_base = 0x0
        self._io_priority = 0
        self._base_priority = 0

    @property
    def pid(self):
        return self._pid

    @property
    def ppid(self):
        return self._ppid

    @property
    def tid(self):
        return self._tid

    @property
    def exe(self):
        return self._exe

    @property
    def name(self):
        return self._name

    @property
    def comm(self):
        return self._comm

    @property
    def args(self):
        return self._args

    @property
    def suid(self):
        return self._suid

    @property
    def child_count(self):
        return self._child_count

    @property
    def handles(self):
        return self._handles

    @handles.setter
    def handles(self, handles):
        self._handles = handles

    @property
    def ustack_base(self):
        return self._ustack_base

    @ustack_base.setter
    def ustack_base(self, ustack_base):
        self._ustack_base = ustack_base

    @property
    def kstack_base(self):
        return self._kstack_base

    @kstack_base.setter
    def kstack_base(self, kstack_base):
        self._kstack_base = kstack_base

    @property
    def io_priority(self):
        return self._io_priority

    @io_priority.setter
    def io_priority(self, io_priority):
        self._io_priority = io_priority

    @property
    def base_priority(self):
        return self._base_priority

    @base_priority.setter
    def base_priority(self, base_priority):
        self._base_priority = base_priority

    def increment_child_count(self):
        self._child_count += 1

    def decrement_child_count(self):
        if self._child_count != 0:
            self._child_count -= 1

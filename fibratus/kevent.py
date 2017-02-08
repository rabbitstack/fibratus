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

from datetime import datetime
from enum import Enum

from fibratus.apidefs.process import open_thread, THREAD_QUERY_INFORMATION, get_process_id_of_thread
from fibratus.apidefs.sys import close_handle
from fibratus.common import DotD as ddict, NA


class Category(Enum):

    REGISTRY = 0
    FILE = 1
    NET = 2
    PROCESS = 3
    THREAD = 4
    MM = 5
    CSWITCH = 6
    SYSCALL = 7
    DISK_IO = 8
    DLL = 9
    OTHER = 10


class KEvents(object):
    """Available kernel event names.
    """
    CREATE_PROCESS = 'CreateProcess'
    CREATE_THREAD = 'CreateThread'
    TERMINATE_PROCESS = 'TerminateProcess'
    TERMINATE_THREAD = 'TerminateThread'

    REG_CREATE_KEY = 'RegCreateKey'
    REG_DELETE_KEY = 'RegDeleteKey'
    REG_DELETE_VALUE = 'RegDeleteValue'
    REG_OPEN_KEY = 'RegOpenKey'
    REG_SET_VALUE = 'RegSetValue'
    REG_QUERY_VALUE = 'RegQueryValue'
    REG_QUERY_KEY = 'RegQueryKey'

    CREATE_FILE = 'CreateFile'
    DELETE_FILE = 'DeleteFile'
    WRITE_FILE = 'WriteFile'
    READ_FILE = 'ReadFile'
    CLOSE_FILE = 'CloseFile'
    RENAME_FILE = 'RenameFile'
    SET_FILE_INFORMATION = 'SetFileInformation'

    SEND = 'Send'
    RECEIVE = 'Recv'
    ACCEPT = 'Accept'
    CONNECT = 'Connect'
    DISCONNECT = 'Disconnect'
    RECONNECT = 'Reconnect'

    LOAD_IMAGE = 'LoadImage'
    UNLOAD_IMAGE = 'UnloadImage'

    SYSCALL_ENTER = 'SyscallEnter'
    SYSCALL_EXIT = 'SyscallExit'

    CONTEXT_SWITCH = 'ContextSwitch'

    @classmethod
    def all(cls):
        return [cls.CREATE_PROCESS,
                cls.CREATE_THREAD,
                cls.TERMINATE_PROCESS,
                cls.TERMINATE_THREAD,
                cls.CREATE_FILE,
                cls.DELETE_FILE,
                cls.READ_FILE,
                cls.WRITE_FILE,
                cls.CLOSE_FILE,
                cls.RENAME_FILE,
                cls.SET_FILE_INFORMATION,
                cls.REG_QUERY_KEY,
                cls.REG_QUERY_VALUE,
                cls.REG_CREATE_KEY,
                cls.REG_DELETE_KEY,
                cls.REG_DELETE_VALUE,
                cls.REG_OPEN_KEY,
                cls.REG_SET_VALUE,
                cls.LOAD_IMAGE,
                cls.UNLOAD_IMAGE,
                cls.SEND,
                cls.RECEIVE,
                cls.ACCEPT,
                cls.CONNECT,
                cls.RECONNECT,
                cls.DISCONNECT,
                cls.CONTEXT_SWITCH]

    @classmethod
    def meta_info(cls):
        kevents = {
            KEvents.CREATE_PROCESS: (Category.PROCESS, 'Creates a new process and its primary thread', ),
            KEvents.CREATE_THREAD: (Category.THREAD, 'Creates a thread to execute within the virtual address space'
                                                     ' of the calling process', ),
            KEvents.TERMINATE_PROCESS: (Category.PROCESS, 'Terminates the process and all of its threads', ),
            KEvents.TERMINATE_THREAD: (Category.THREAD, 'Terminates a thread', ),
            KEvents.CREATE_FILE: (Category.FILE, 'Creates or opens a file or I/O device', ),
            KEvents.DELETE_FILE: (Category.FILE, 'Deletes an existing file or directory', ),
            KEvents.READ_FILE: (Category.FILE, 'Reads data from the file or I/O device', ),
            KEvents.WRITE_FILE: (Category.FILE, 'Writes data to the file or I/O device', ),
            KEvents.CLOSE_FILE: (Category.FILE, 'Closes the file or I/O device', ),
            KEvents.SET_FILE_INFORMATION: (Category.FILE, 'Changes information for the specified file',),
            KEvents.RENAME_FILE: (Category.FILE, 'Renames a file or directory', ),
            KEvents.REG_QUERY_KEY: (Category.REGISTRY, 'Retrieves information about the registry key', ),
            KEvents.REG_OPEN_KEY: (Category.REGISTRY, 'Opens the registry key', ),
            KEvents.REG_CREATE_KEY: (Category.REGISTRY, 'Creates the registry key or open it if the key '
                                                        'already exists', ),
            KEvents.REG_DELETE_KEY: (Category.REGISTRY, 'Deletes a subkey and its values', ),
            KEvents.REG_QUERY_VALUE: (Category.REGISTRY, 'Retrieves the type and data of the value'
                                                         ' associated with an open registry key', ),
            KEvents.REG_DELETE_VALUE: (Category.REGISTRY, 'Removes a value from the registry key', ),
            KEvents.REG_SET_VALUE: (Category.REGISTRY, 'Sets the data and type of a value under a registry key', ),
            KEvents.LOAD_IMAGE: (Category.DLL, 'Loads the module into the address space of the calling process', ),
            KEvents.UNLOAD_IMAGE: (Category.DLL, 'Frees the loaded module from the address space '
                                                 'of the calling process', ),
            KEvents.SEND: (Category.NET, 'Sends data on a connected socket', ),
            KEvents.RECEIVE: (Category.NET, 'Receives data from a connected socket', ),
            KEvents.ACCEPT: (Category.NET, 'Initiates the connection attempt from the remote or local TCP socket', ),
            KEvents.CONNECT: (Category.NET, 'Establishes the connection to a TCP socket', ),
            KEvents.RECONNECT: (Category.NET, 'Reconnects to a TCP socket', ),
            KEvents.DISCONNECT: (Category.NET, 'Closes the connection to a TCP socket', ),

            KEvents.CONTEXT_SWITCH: (Category.THREAD, 'Scheduler selects a new thread to execute',)}
        return kevents

__kevents__ = KEvents.meta_info()


class KEvent(object):

    def __init__(self, thread_registry):
        self._kid = 0
        self._ts = datetime.now()
        self._cpuid = 0
        self._name = None
        self._category = None
        self._params = {}
        self._tid = None
        self._pid = None
        self.thread_registry = thread_registry

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        self._name = name
        if name in __kevents__:
            cat, _ = __kevents__[name]
            self._category = cat.name

    @property
    def params(self):
        return self._params

    @params.setter
    def params(self, params):
        self._params = ddict(params)

    @property
    def ts(self):
        return self._ts

    @ts.setter
    def ts(self, ts):
        self._ts = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S.%f')

    @property
    def cpuid(self):
        return self._cpuid

    @cpuid.setter
    def cpuid(self, cpuid):
        self._cpuid = cpuid

    @property
    def category(self):
        return self._category

    @property
    def pid(self):
        return self._pid

    @pid.setter
    def pid(self, pid):
        self._pid = pid

    @property
    def tid(self):
        return self._tid

    @tid.setter
    def tid(self, tid):
        self._tid = tid

    @property
    def kid(self):
        return self._kid

    @property
    def thread(self):
        return self._find_thread()

    def _find_thread(self):
        """Finds the current thread/process emitted by the kernel event.
        """
        if self._pid:
            # first lookup by process id
            # if the process doesn't exist
            # in the thread registry
            # then query by the thread id
            thread = self.thread_registry.get_thread(self._pid)
            if not thread and self._tid:
                thread = self.thread_registry.get_thread(self._tid)
        else:
            # we dont have the process id
            # try to find the thread from which
            # we can get the process
            thread = self.thread_registry.get_thread(self._tid)
        return thread

    def get_thread(self):
        """Gets the thread associated with the kernel event.
        """
        thread = self._find_thread()
        if thread:
            return thread.pid, thread.name
        else:
            # figure out the process id from thread
            # if the process can't be found in
            # the thread registry
            pid = NA
            if self._pid is None:
                if self._tid:
                    # get the thread handle
                    handle = open_thread(THREAD_QUERY_INFORMATION,
                                         False,
                                         self._tid)
                    if handle:
                        pid = get_process_id_of_thread(handle)
                        close_handle(handle)
            else:
                pid = self._pid
            return pid, NA

    def inc_kid(self):
        self._kid += 1



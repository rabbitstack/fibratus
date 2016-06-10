# Copyright 2015 by Nedim Sabic (RabbitStack)
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

from kstreamc import KEventStreamCollector
from logbook import Logger, FileHandler

import atexit
import os
import fibratus.apidefs.etw as etw
from fibratus.controller import KTraceController, KTraceProps
from fibratus.dll import DllRepository
from fibratus.fs import FsIO
from fibratus.handle import HandleRepository
from fibratus.kevent import KEvent
from fibratus.kevent_types import *
from fibratus.common import DotD as ddict, IO
from fibratus.registry import HiveParser
from fibratus.tcpip import TcpIpParser
from fibratus.thread import ThreadRegistry


class Fibratus(object):

    """Fibratus entrypoint.

    Setup the core components including the kernel
    event stream collector and the tracing controller.
    At this point the system handles are also being
    enumerated.

    """
    def __init__(self, filament):

        self.logger = Logger(Fibratus.__name__)
        self.file_handler = FileHandler(os.path.join(os.path.abspath(__file__), '..', '..', '..', 'fibratus.log'),
                                        mode='w+')
        self.kevt_streamc = KEventStreamCollector(etw.KERNEL_LOGGER_NAME.encode())
        self.kcontroller = KTraceController()
        self.ktrace_props = KTraceProps()
        self.ktrace_props.enable_kflags()
        self.ktrace_props.logger_name = etw.KERNEL_LOGGER_NAME

        self.handle_repository = HandleRepository()
        self._handles = []
        # query for handles on the
        # start of kernel trace
        with self.file_handler.applicationbound():
            self.logger.info('Starting fibratus...')
            self.logger.info('Enumerating system handles...')
            self._handles = self.handle_repository.query_handles()
            self.logger.info('%s handles found' % len(self._handles))
            self.handle_repository.free_buffers()
        self.thread_registry = ThreadRegistry(self.handle_repository, self._handles)

        self.kevent = KEvent(self.thread_registry)

        self._filament = filament

        self.fsio = FsIO(self.kevent, self._handles)
        self.hive_parser = HiveParser(self.kevent, self.thread_registry)
        self.tcpip_parser = TcpIpParser(self.kevent)
        self.dll_repository = DllRepository(self.kevent)

        self.requires_render = {}
        self.filters_count = 0

    def run(self):

        @atexit.register
        def _exit():
            self.stop_ktrace()

        self.kcontroller.start_ktrace(etw.KERNEL_LOGGER_NAME, self.ktrace_props)

        def on_kstream_open():
            if self._filament is None:
                IO.write_console('Done!                               ')
        self.kevt_streamc.set_kstream_open_callback(on_kstream_open)
        self._open_kstream()

    def _open_kstream(self):
        try:
            self.kevt_streamc.open_kstream(self._on_next_kevent)
        except Exception as e:
            with self.file_handler.applicationbound():
                self.logger.error(e)
        except KeyboardInterrupt:
            self.stop_ktrace()

    def stop_ktrace(self):
        IO.write_console('Stopping fibratus...')
        if self._filament:
            self._filament.close()
        self.kcontroller.stop_ktrace(self.ktrace_props)
        self.kevt_streamc.close_kstream()

    def add_filters(self, kevent_filters):
        if len(kevent_filters) > 0:
            self.filters_count = len(kevent_filters)
            # include the basic filters
            # that are essential to the
            # rest of kernel events
            self.kevt_streamc.add_kevent_filter(ENUM_PROCESS)
            self.kevt_streamc.add_kevent_filter(ENUM_THREAD)
            self.kevt_streamc.add_kevent_filter(ENUM_IMAGE)
            self.kevt_streamc.add_kevent_filter(REG_CREATE_KCB)
            self.kevt_streamc.add_kevent_filter(REG_DELETE_KCB)

            # these kevents are necessary for consistent state
            # of the trace. If the user doesn't include them
            # in a filter list, then we do the job but set the
            # kernel event type as not eligible for rendering
            if KEvents.CREATE_PROCESS not in kevent_filters:
                self.kevt_streamc.add_kevent_filter(CREATE_PROCESS)
                self.requires_render[CREATE_PROCESS] = False
            else:
                self.requires_render[CREATE_PROCESS] = True

            if KEvents.CREATE_THREAD not in kevent_filters:
                self.kevt_streamc.add_kevent_filter(CREATE_THREAD)
                self.requires_render[CREATE_THREAD] = False
            else:
                self.requires_render[CREATE_THREAD] = True

            if KEvents.CREATE_FILE not in kevent_filters:
                self.kevt_streamc.add_kevent_filter(CREATE_FILE)
                self.requires_render[CREATE_FILE] = False
            else:
                self.requires_render[CREATE_FILE] = True

            for kevent_filter in kevent_filters:
                ktuple = kname_to_tuple(kevent_filter)
                if isinstance(ktuple, list):
                    for kt in ktuple:
                        self.kevt_streamc.add_kevent_filter(kt)
                        if kt not in self.requires_render:
                            self.requires_render[kt] = True
                else:
                    self.kevt_streamc.add_kevent_filter(ktuple)
                    if ktuple not in self.requires_render:
                        self.requires_render[ktuple] = True

    def _on_next_kevent(self, ktype, cpuid, ts, kparams):
        """Callback which fires when new kernel event arrives.

        This callback is invoked for every new kernel event
        forwarded from the kernel stream collector.

        Parameters
        ----------

        ktype: tuple
            Kernel event type.
        cpuid: int
            Indentifies the CPU core where the event
            has been captured.
        ts: str
            Temporal reference of the kernel event.
        kparams: dict
            Kernel event's parameters.
        """

        # initialize kernel event properties
        self.kevent.ts = ts
        self.kevent.cpuid = cpuid
        self.kevent.name = ktuple_to_name(ktype)
        kparams = ddict(kparams)
        # thread / process kernel events
        if ktype in [CREATE_PROCESS,
                     CREATE_THREAD,
                     ENUM_PROCESS,
                     ENUM_THREAD]:
            self.thread_registry.add_thread(ktype, kparams)
            if ktype in [CREATE_PROCESS, CREATE_THREAD]:
                self.thread_registry.init_thread_kevent(self.kevent,
                                                        ktype,
                                                        kparams)
                self._render(ktype)
        elif ktype in [TERMINATE_PROCESS, TERMINATE_THREAD]:
            self.thread_registry.init_thread_kevent(self.kevent,
                                                    ktype,
                                                    kparams)
            self._render(ktype)
            self.thread_registry.remove_thread(ktype, kparams)

        # file system/disk kernel events
        elif ktype in [CREATE_FILE,
                       DELETE_FILE,
                       CLOSE_FILE,
                       READ_FILE,
                       WRITE_FILE]:
            self.fsio.parse_fsio(ktype, kparams)
            self._render(ktype)

        # dll kernel events
        elif ktype in [LOAD_IMAGE, ENUM_IMAGE]:
            self.dll_repository.register_dll(kparams)
            if ktype == LOAD_IMAGE:
                self._render(ktype)
        elif ktype == UNLOAD_IMAGE:
            self.dll_repository.unregister_dll(kparams)
            self._render(ktype)

        # registry kernel events
        elif ktype == REG_CREATE_KCB:
            self.hive_parser.add_kcb(kparams)
        elif ktype == REG_DELETE_KCB:
            self.hive_parser.remove_kcb(kparams.key_handle)

        elif ktype in [REG_CREATE_KEY,
                       REG_DELETE_KEY,
                       REG_OPEN_KEY,
                       REG_QUERY_KEY,
                       REG_SET_VALUE,
                       REG_DELETE_VALUE,
                       REG_QUERY_VALUE]:
            self.hive_parser.parse_hive(ktype, kparams)
            self._render(ktype)

        # network kernel events
        elif ktype in [SEND_SOCKET_TCPV4,
                       SEND_SOCKET_UDPV4,
                       RECV_SOCKET_TCPV4,
                       RECV_SOCKET_UDPV4,
                       ACCEPT_SOCKET_TCPV4,
                       CONNECT_SOCKET_TCPV4,
                       DISCONNECT_SOCKET_TCPV4,
                       RECONNECT_SOCKET_TCPV4]:
            self.tcpip_parser.parse_tcpip(ktype, kparams)
            self._render(ktype)

        if self._filament:
            # call filament method
            # to process the next
            # kernel event from the stream
            if ktype not in [ENUM_PROCESS,
                             ENUM_THREAD, ENUM_IMAGE]:
                if self.kevent.name:
                    self._filament.process(self.kevent)

    def _render(self, ktype):
        """Renders the kevent to the standard output stream.

        Parameters
        ----------

        ktype: tuple
            Identifier of the kernel event
        """
        if not self._filament:
            if ktype in self.requires_render:
                rr = self.requires_render[ktype]
                if rr:
                    self.kevent.render()
            elif self.filters_count == 0:
                self.kevent.render()

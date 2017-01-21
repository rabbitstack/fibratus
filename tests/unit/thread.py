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
from unittest.mock import patch, Mock

import pytest
import os

from fibratus.apidefs.cdefs import ERROR_ACCESS_DENIED
from fibratus.apidefs.process import PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ
from fibratus.handle import HandleRepository, HandleInfo
from fibratus.image_meta import ImageMetaRegistry
from fibratus.kevent_types import CREATE_PROCESS, CREATE_THREAD, ENUM_PROCESS, ENUM_THREAD, TERMINATE_THREAD, \
    TERMINATE_PROCESS
from fibratus.common import DotD as dd
from fibratus.thread import ThreadRegistry, ThreadInfo


@pytest.fixture(scope='module')
def handle_repo_mock():
    handle_repo = Mock(spec_set=HandleRepository)
    handle_repo.query_handles.return_value = [HandleInfo(20, 18446738026501927904, 'FILE',
                                                         'C:\\Windows\\System32\\kernel32.dll',
                                                         0x2d8)]
    return handle_repo


@pytest.fixture(scope='module')
def image_meta_registry_mock():
    return Mock(spec_set=ImageMetaRegistry)


@pytest.fixture(scope='module')
def thread_registry(handle_repo_mock, image_meta_registry_mock):
    p1 = {"session_id": 0, "command_line": "C:\\Windows\\system32\\services.exe", "process_id": "0x1e4",
          "unique_process_key": 18446738026492816176, "exit_status": 259,
          "parent_id": "0x17c",
          "image_file_name": "services.exe",
          "directory_table_base": 4299976704,
          "user_sid": None}
    t1 = {"user_stack_base": 14483456, "io_priority": 2, "teb_base": 8796092874752, "process_id": "0x1e4",
          "stack_limit": 18446735827441688576, "t_thread_id": "0x238", "base_priority": 9,
          "win32_start_addr": 2009573488, "page_priority": 5,
          "stack_base": 18446735827441713152, "user_stack_limit": 14450688,
          "thread_flags": 0, "affinity": 15, "sub_process_tag": "0x0"}
    t2 = {"user_stack_base": 16580608, "io_priority": 2, "teb_base": 8796092669952, "process_id": "0x1e4",
          "stack_limit": 18446735827442425856, "t_thread_id": "0x254", "base_priority": 9,
          "win32_start_addr": 8791752742020, "page_priority": 5,
          "stack_base": 18446735827442450432, "user_stack_limit": 16547840,
          "thread_flags": 0, "affinity": 15, "sub_process_tag": "0x0"}

    thread_registry = ThreadRegistry(handle_repo_mock, [], image_meta_registry_mock)
    thread_registry.add_thread(ENUM_PROCESS, dd(p1))
    thread_registry.add_thread(ENUM_THREAD, dd(t1))
    thread_registry.add_thread(ENUM_THREAD, dd(t2))

    return thread_registry


class TestThreadRegistry():

    def test_init_thread_registry(self, thread_registry):

        assert len(thread_registry.threads) == 3
        proc = thread_registry.threads[int('0x1e4', 16)]
        assert proc
        assert isinstance(proc, ThreadInfo)
        assert proc.child_count == 2

    def test_enum_process(self, thread_registry, handle_repo_mock):

        kti = dd({"session_id": 0, "command_line": "C:\\Windows\\system32\\svchost.exe -k RPCSS",
                  "process_id": "0x2d8",
                  "unique_process_key": 18446738026496154416,
                  "exit_status": 259, "user_sid": None, "parent_id": "0x1e4",
                  "image_file_name": "svchost.exe", "directory_table_base": 3716534272})
        thread_registry.add_thread(ENUM_PROCESS, kti)
        process_id = int(kti.process_id, 16)

        handle_repo_mock.query_handles.assert_not_called()

        t = thread_registry.get_thread(process_id)
        assert t

        assert t.pid == process_id
        assert t.ppid == int(kti.parent_id, 16)
        assert t.name == kti.image_file_name
        assert t.exe == 'C:\\Windows\\system32\\svchost.exe'
        assert t.comm == kti.command_line
        assert len(t.args) > 0
        assert ['-k', 'RPCSS'] == t.args
        assert '-k' in t.args
        assert 'RPCSS' in t.args

    def test_create_process(self, thread_registry, handle_repo_mock):

        kti = dd({"session_id": 4294967295, "command_line": "\\SystemRoot\\System32\\smss.exe",
                  "process_id": "0xfc", "unique_process_key": 18446738026484345648, "exit_status": 259,
                  "user_sid": None, "parent_id": "0x4", "image_file_name": "smss.exe",
                  "directory_table_base": 4508921856})
        thread_registry.add_thread(CREATE_PROCESS, kti)
        process_id = int(kti.process_id, 16)

        t = thread_registry.get_thread(process_id)
        sys_root = os.path.expandvars("%SystemRoot%")
        assert t
        assert t.pid == process_id
        assert t.ppid == int(kti.parent_id, 16)
        assert t.name == kti.image_file_name
        assert t.exe == '%s\\System32\\smss.exe' % sys_root
        assert t.comm == kti.command_line
        assert len(t.args) == 0

    def test_create_thread(self, thread_registry):

        kti = dd({"user_stack_base": 18874368, "io_priority": 2, "teb_base": 8796092882944,
                 "process_id": "0x1e4", "stack_limit": 18446735827462836224,
                 "t_thread_id": "0x57c", "base_priority": 9, "win32_start_addr": 2009592544,
                 "page_priority": 5, "stack_base": 18446735827462860800,
                 "user_stack_limit": 18841600, "thread_flags": 0,
                 "affinity": 15, "sub_process_tag": "0x0"})
        thread_registry.add_thread(CREATE_THREAD, kti)
        thread_id = int(kti.t_thread_id, 16)
        t = thread_registry.get_thread(thread_id)
        assert t
        assert t.tid == thread_id
        assert t.pid == t.ppid == int(kti.process_id, 16)
        assert t.kstack_base == hex(kti.stack_base)
        assert t.ustack_base == hex(kti.user_stack_base)
        assert t.base_priority == kti.base_priority
        assert t.io_priority == kti.io_priority
        assert t.child_count == 0

    @patch('fibratus.thread.open_process', return_value=13)
    @patch('fibratus.thread.close_handle', return_value=None)
    def test_create_thread_registry_proc_lookup_failed(self, close_handle_mock, open_process_mock,
                                                       thread_registry, handle_repo_mock):

        kti = dd({"user_stack_base": 10289152, "io_priority": 2, "teb_base": 8796092874752,
                  "process_id": "0x330", "stack_limit": 18446735827443150848, "t_thread_id": "0x338",
                  "base_priority": 8, "win32_start_addr": 2009573488,
                  "page_priority": 5, "stack_base": 18446735827443175424, "user_stack_limit": 10256384,
                  "thread_flags": 0, "affinity": 15, "sub_process_tag": "0x0"})
        thread_id = int(kti.t_thread_id, 16)
        process_id = int(kti.process_id, 16)

        with patch('fibratus.thread.ThreadRegistry._query_process_info', return_value=dd(name='Dwm.exe',
                   comm='C:\\Windows\\system32\\Dwm.exe',
                   parent_pid=0x748)) as query_process_info_mock:
            thread_registry.add_thread(CREATE_THREAD, kti)
            open_process_mock.assert_called_with(PROCESS_QUERY_INFORMATION |
                                                 PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                                                 False, process_id)
            query_process_info_mock.assert_called_with(13)
            close_handle_mock.assert_called_with(13)

        handle_repo_mock.query_handles.assert_called_with(process_id)

        proc = thread_registry.get_thread(process_id)
        assert proc
        assert proc.name == 'dwm.exe'
        t = thread_registry.get_thread(thread_id)
        assert t
        assert t.name == 'dwm.exe'


    @patch('fibratus.thread.open_process', side_effect=[None, 29])
    @patch('fibratus.thread.close_handle', return_value=None)
    @patch('fibratus.thread.get_last_error', return_value=ERROR_ACCESS_DENIED)
    def test_create_thread_registry_proc_lookup_failed_invalid_handle(self, get_last_error, close_handle_mock,
                                                                      open_process_mock,
                                                                      thread_registry, handle_repo_mock):

        kti = dd({"user_stack_base": 1835008, "io_priority": 2, "teb_base": 8796092878848,
                  "process_id": "0x4c8", "stack_limit": 18446735827446923264, "t_thread_id": "0x4dc",
                  "base_priority": 8, "win32_start_addr": 4286166856, "page_priority": 5,
                  "stack_base": 18446735827446964224,
                  "user_stack_limit": 1744896, "thread_flags": 0, "affinity": 15, "sub_process_tag": "0x0"})
        thread_id = int(kti.t_thread_id, 16)
        process_id = int(kti.process_id, 16)

        with patch('fibratus.thread.ThreadRegistry._query_process_info', return_value=dd(name='explorer.exe',
                   comm='C:\\Windows\\Explorer.EXE',
                   parent_pid=0x4c8)) as query_process_info_mock:
            thread_registry.add_thread(CREATE_THREAD, kti)
            assert get_last_error.call_count == 1
            open_process_mock.assert_called_with(PROCESS_QUERY_LIMITED_INFORMATION,
                                                 False, process_id)

            query_process_info_mock.assert_called_with(29, False)
            close_handle_mock.assert_called_with(29)

        handle_repo_mock.query_handles.assert_called_with(process_id)

        proc = thread_registry.get_thread(process_id)
        assert proc
        assert proc.name == 'explorer.exe'
        t = thread_registry.get_thread(thread_id)
        assert t
        assert t.name == 'explorer.exe'
        assert t.comm == 'C:\\Windows\\Explorer.EXE'

    def test_terminate_thread(self, thread_registry):

        kti = dd({"user_stack_base": 18874368, "io_priority": 2, "teb_base": 8796092882944,
                 "process_id": "0x1e4", "stack_limit": 18446735827462836224,
                 "t_thread_id": "0x57c", "base_priority": 9, "win32_start_addr": 2009592544,
                 "page_priority": 5, "stack_base": 18446735827462860800,
                 "user_stack_limit": 18841600, "thread_flags": 0,
                 "affinity": 15, "sub_process_tag": "0x0"})

        thread_id = int(kti.t_thread_id, 16)
        process_id = int(kti.process_id, 16)
        proc = thread_registry.get_thread(process_id)

        child_count = proc.child_count
        t = thread_registry.get_thread(thread_id)
        assert t
        thread_registry.remove_thread(TERMINATE_THREAD, kti)

        t = thread_registry.get_thread(thread_id)
        assert t is None
        assert proc.child_count == child_count - 1

    def test_terminate_process(self, thread_registry):
        kti = dd({"session_id": 0, "command_line": "C:\\Windows\\system32\\services.exe", "process_id": "0x1e4",
                  "unique_process_key": 18446738026492816176, "exit_status": 259,
                  "parent_id": "0x17c",
                  "image_file_name": "services.exe",
                  "directory_table_base": 4299976704,
                  "user_sid": None})
        process_id = int(kti.process_id, 16)
        proc = thread_registry.get_thread(process_id)
        assert proc
        thread_registry.remove_thread(TERMINATE_PROCESS, kti)
        proc = thread_registry.get_thread(process_id)
        assert proc is None
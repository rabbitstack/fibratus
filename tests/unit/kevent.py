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
from unittest.mock import Mock, patch

import pytest
from fibratus.apidefs.process import THREAD_QUERY_INFORMATION
from fibratus.common import DotD

from fibratus.kevent import KEvent, KEvents, Category
from fibratus.thread import ThreadRegistry, ThreadInfo


@pytest.fixture(scope='module')
def thread_registry_mock():
    thread_registry = Mock(spec_set=ThreadRegistry)
    thread_registry.get_thread.side_effect = [ThreadInfo(436, 1024, 23, 'svchost.exe',
                                                         'C:\\Windows\\system32\\svchost.exe -k RPCSS', None),
                                              None,
                                              None,
                                              ThreadInfo(836, 564, 23, 'svchost.exe',
                                                         'C:\\Windows\\system32\\svchost.exe -k RPCSS', None),
                                              ThreadInfo(836, 564, 23, 'svchost.exe',
                                                         'C:\\Windows\\system32\\svchost.exe -k RPCSS', None),
                                              ThreadInfo(836, 564, 23, 'svchost.exe',
                                                         'C:\\Windows\\system32\\svchost.exe -k RPCSS', None),
                                              None, None]
    return thread_registry

@pytest.fixture()
def kevent(thread_registry_mock):
    kevt = KEvent(thread_registry_mock)
    return kevt


class TestKEvent():

    def test_get_thread_pid_not_none(self, kevent, thread_registry_mock):
        kevent.pid = 436
        assert kevent.thread
        thread_registry_mock.get_thread.assert_called_with(kevent.pid)

    def test_get_thread_pid_not_none_and_not_found_in_registry(self, kevent, thread_registry_mock):
        kevent.pid = 436
        assert kevent.thread is None
        thread_registry_mock.get_thread.assert_called_with(kevent.pid)

    def test_get_thread_pid_not_none_find_by_thread(self, kevent, thread_registry_mock):
        kevent.pid = 436
        kevent.tid = 564
        assert kevent.thread
        thread_registry_mock.get_thread.assert_called_with(kevent.tid)

    def test_get_thread_pid_none(self, kevent, thread_registry_mock):
        kevent.tid = 564
        assert kevent.thread
        thread_registry_mock.get_thread.assert_called_with(kevent.tid)

    @patch('fibratus.kevent.IO.write_console')
    def test_render(self, write_console_mock, kevent):
        assert kevent.id == 0
        kevent.render()
        assert write_console_mock.called
        assert kevent.id == 1

    @patch('fibratus.kevent.open_thread', return_value=25)
    @patch('fibratus.kevent.get_process_id_of_thread')
    @patch('fibratus.kevent.close_handle')
    def test_render_pid_none(self, close_handle_mock, get_process_id_of_thread_mock, open_thread_mock,
                             kevent):
        kevent.tid = 245
        kevent.render()
        open_thread_mock.assert_called_with(THREAD_QUERY_INFORMATION,
                                            False, kevent.tid)
        get_process_id_of_thread_mock.assert_called_with(25)
        close_handle_mock.assert_called_with(25)

    def test_render_pid_not_found_in_registry(self, kevent):
        kevent.pid = 836
        kevent.render()

    def test_kevents_all(self):
        kevents = KEvents.all()
        assert isinstance(kevents, list)
        assert len(kevents) == 25

    def test_kevents_meta_info(self):
        kevents_meta_info = KEvents.meta_info()
        assert isinstance(kevents_meta_info, dict)
        cat, description = kevents_meta_info[KEvents.CREATE_PROCESS]
        assert cat == Category.PROCESS
        assert description

    def test_set_kevent_name(self, kevent):
        kevent.name = KEvents.CREATE_PROCESS
        assert kevent.name == KEvents.CREATE_PROCESS
        assert kevent.category == Category.PROCESS.name

    def test_set_kevent_ts(self, kevent):
        kevent.ts = '12:31:48.210000'
        assert kevent.ts.second == 48
        assert kevent.ts.minute == 31
        assert kevent.ts.hour == 12

    def test_set_kevent_cpu_id(self, kevent):
        kevent.cpuid = 2
        assert kevent.cpuid == 2

    def test_set_kevent_params(self, kevent):
        kevent.params = {'exe': 'svchost.exe', 'comm': 'C:\\Windows\\system32\\svchost.exe -k RPCSS'}
        assert isinstance(kevent.params, DotD)
        assert kevent.params.exe == 'svchost.exe'


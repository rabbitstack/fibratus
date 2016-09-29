# Copyright 2016 by Nedim Sabic (RabbitStack)
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
from unittest.mock import Mock, call

from datetime import datetime
import pytest

from fibratus.context_switch import ContextSwitchRegistry, ThreadState, ThreadWaitMode
from fibratus.kevent import KEvent
from fibratus.thread import ThreadRegistry, ThreadInfo
from fibratus.common import DotD as ddict


@pytest.fixture(scope='module')
def thread_registry_mock():
    thread_registry = Mock(spec_set=ThreadRegistry)
    thread_info1 = ThreadInfo(456, int('0x1054', 16), 22, 'explorer.exe', 'C:\\Windows\\EXPLORER.exe', None)
    thread_info2 = ThreadInfo(1, int('0x0', 16), 2, 'system.exe', 'C:\\Windows\\system.exe', None)
    thread_registry.get_thread.side_effect = [thread_info1, thread_info2]
    return thread_registry


@pytest.fixture(scope='module')
def thread_registry_empty_mock():
    return Mock(spec_set=ThreadRegistry)


@pytest.fixture(scope='module')
def kevent_mock():
    return Mock(spec_set=KEvent)


class TestContextSwitchRegistry(object):

    def test_next_cswitch(self, thread_registry_mock, kevent_mock):

        context_switch_registry = ContextSwitchRegistry(thread_registry_mock, kevent_mock)
        ts = datetime.strptime("12:05:45.233", '%H:%M:%S.%f')
        kcs1 = ddict({'old_thread_wait_ideal_processor': 2, 'previous_c_state': 1, 'old_thread_state': 2,
                      'old_thread_priority': 0, 'reserved': 777748717, 'spare_byte': 0,
                      'old_thread_wait_reason': 0, 'new_thread_wait_time': '0x0', 'old_thread_wait_mode': 0,
                      'new_thread_priority': 15, 'new_thread_id': '0x1054', 'old_thread_id': '0x0'})
        new_thread_id = int(kcs1.new_thread_id, 16)
        context_switch_registry.next_cswitch(1, ts, kcs1)

        thread_registry_mock.get_thread.assert_has_calls([call(new_thread_id),
                                                         call(int(kcs1.old_thread_id, 16))])

        assert (1, new_thread_id,) in context_switch_registry.context_switches()
        cs = context_switch_registry.context_switches()[(1, new_thread_id,)]
        assert cs

        assert cs.timestamp is ts
        assert cs.next_proc_name == "explorer.exe"
        assert cs.next_thread_wait_time == 0
        assert cs.next_thread_prio == 15
        assert cs.prev_thread_prio == 0
        assert cs.prev_thread_state is ThreadState.RUNNING
        assert cs.count == 1
        assert cs.prev_thread_wait_mode is ThreadWaitMode.KERNEL

    def test_next_cswitch_in_registry(self, thread_registry_empty_mock, kevent_mock):
        context_switch_registry = ContextSwitchRegistry(thread_registry_empty_mock, kevent_mock)

        kcs1 = ddict({'old_thread_wait_ideal_processor': 3, 'previous_c_state': 0, 'old_thread_state': 5,
                      'old_thread_priority': 8, 'reserved': 4294967294, 'spare_byte': 0,
                      'old_thread_wait_reason': 17, 'new_thread_wait_time': '0x0', 'old_thread_wait_mode': 1,
                      'new_thread_priority': 8, 'new_thread_id': '0x1fc8', 'old_thread_id': '0x2348'})
        kcs2 = ddict({'old_thread_wait_ideal_processor': 3, 'previous_c_state': 0, 'old_thread_state': 3,
                      'old_thread_priority': 8, 'reserved': 4294967295, 'spare_byte': 0,
                      'old_thread_wait_reason': 17, 'new_thread_wait_time': '0x0', 'old_thread_wait_mode': 1,
                      'new_thread_priority': 5, 'new_thread_id': '0x1fc8', 'old_thread_id': '0x2348'})

        context_switch_registry.next_cswitch(1, datetime.strptime("12:05:45.233", '%H:%M:%S.%f'), kcs1)
        context_switch_registry.next_cswitch(1, datetime.strptime("12:05:45.234", '%H:%M:%S.%f'), kcs2)

        k = (1, int(kcs1.new_thread_id, 16))
        cs = context_switch_registry.context_switches()[k]
        assert cs
        assert cs.count == 2
        assert cs.next_thread_prio == 5
        assert cs.prev_thread_state is ThreadState.STANDBY
        assert cs.timestamp == datetime.strptime("12:05:45.234", '%H:%M:%S.%f')

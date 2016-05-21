# Copyright 2015/2016 by Nedim Sabic (RabbitStack)
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

import os
from unittest.mock import patch, call

import pytest

from fibratus.apidefs.process import PROCESS_DUP_HANDLE
from fibratus.handle import HandleRepository, HandleType
from fibratus.common import DotD as dd


def raw_handles():
    handles = {}
    handles[18446738026470543136] = dd(obj=18446738026470543136, handle=12, pid=3472, access_mask=1048608, obj_type_index=28)
    handles[18446738026474344592] = dd(obj=18446738026474344592, handle=16, pid=3472, access_mask=2031617, obj_type_index=36)
    handles[18446738026474569824] = dd(obj=18446738026474569824, handle=204, pid=920, access_mask=1048578, obj_type_index=17)
    handles[18446738026469227424] = dd(obj=18446738026469227424, handle=116, pid=920, access_mask=2031619, obj_type_index=12)
    handles[18446735964891181152] = dd(obj=18446735964891181152, handle=108, pid=1616, access_mask=983551, obj_type_index=5)
    return handles


def query_handle_side_effects():
    return [dd(contents=dd(type_name=dd(buffer="FILE"))), dd(contents=dd(buffer="\Device\HarddiskVolume2"))] \
        * len(raw_handles())


@pytest.fixture(scope='module')
def handle_repo():
    return HandleRepository()


class TestHandleRepository():

    def test_init_handle_repository(self, handle_repo):
        handle_types = handle_repo._handle_types
        assert isinstance(handle_types, list)
        assert HandleType.FILE.name in handle_types

    @patch('fibratus.handle.HandleRepository._enum_handles', return_value=raw_handles())
    @patch('fibratus.handle.open_process', side_effect=[None, 200, 301, 120, 343])
    @patch('fibratus.handle.duplicate_handle', side_effect=[1, 1, 1, 0])
    @patch('fibratus.handle.HandleRepository._query_handle', side_effect=query_handle_side_effects())
    @patch('fibratus.handle.close_handle')
    @patch('fibratus.handle.get_current_process', return_value=os.getpid())
    @patch('fibratus.handle.cast', return_value=dd(value='FILE'))
    @patch('fibratus.handle.byref', return_value=0x100)
    def test_query_handles(self, byref_mock, cast_mock, get_current_process_mock, close_handle_mock,
                           query_handle_mock, duplicate_handle_mock, open_process_mock,
                           enum_handles_mock, handle_repo):
        handles = handle_repo.query_handles()
        assert enum_handles_mock.called
        assert get_current_process_mock.called

        open_process_expected_calls = [call(PROCESS_DUP_HANDLE, False, 3472), call(PROCESS_DUP_HANDLE, False, 3472),
                                       call(PROCESS_DUP_HANDLE, False, 920),
                                       call(PROCESS_DUP_HANDLE, False, 920),
                                       call(PROCESS_DUP_HANDLE, False, 1616)]
        open_process_mock.assert_has_calls(open_process_expected_calls, any_order=True)

        assert duplicate_handle_mock.call_count == 4
        assert query_handle_mock.call_count == 6
        assert close_handle_mock.call_count == 7

        assert len(handles) == 3
        assert len([h for h in handles if h.handle_type == HandleType.FILE]) > 0
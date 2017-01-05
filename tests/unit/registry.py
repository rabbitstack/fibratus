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

from fibratus.apidefs.registry import HKEY_LOCAL_MACHINE, HKEY_USERS
from fibratus.common import DotD as dd, NA
from fibratus.handle import HandleInfo, HandleType
from fibratus.kevent import KEvent
from fibratus.kevent_types import *
from fibratus.registry import HiveParser, Kcb
from fibratus.thread import ThreadRegistry, ThreadInfo


@pytest.fixture(scope='module')
def kevent_mock():
    return Mock(spec_set=KEvent)


@pytest.fixture(scope='module')
def thread_registry_mock():
    thread_registry = Mock(spec_set=ThreadRegistry)
    thread_info = ThreadInfo(896, 2916, 22, 'explorer.exe', 'C:\\Windows\\EXPLORER.exe')
    thread_info.handles.append(HandleInfo(836, 18446735964859105184, HandleType.KEY,
                               "\\REGISTRY\\USER\\S-1-5-21-2945379629-2233710143-2353048178-1000_CLASSES\\Local Settings"
                               "\\Software\Microsoft\\Windows\\Shell\\Bags\\59\\Shell\\{5C4F28B5-F869-4E84-8E60-F11DB97C5CC7}",
                               896))
    thread_registry.get_thread.return_value = thread_info
    return thread_registry


@pytest.fixture(scope='module')
def hive_parser(kevent_mock, thread_registry_mock):
    kcb1 = dd({"index": 0, "process_id": 1224, "status": 0, "key_handle": 18446735964840821928,
              "key_name": "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\"
                          "{4a33e644-94a8-11e5-a0c5-806e6f6e6963}\\",
              "thread_id": 1484, "initial_time": 24218562806})
    kcb2 = dd({'initial_time': 0, 'index': 0, 'thread_id': 620, 'status': 0, 'key_handle': 18446735964896987168,
               'key_name': '\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\services\\HDAudBus', 'process_id': 3820})
    kcb3 = dd({"index": 0, "process_id": 896, "status": 0, "key_handle": 18446735964812642928,
               "key_name": "\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\CLSID\\{D2D588B5-D081-11D0-99E0-00C04FC2F8EC}"
                           "\\InprocServer32", "thread_id": 2916, "initial_time": 0})
    hive_parser = HiveParser(kevent_mock, thread_registry_mock)
    hive_parser.add_kcb(kcb1)
    hive_parser.add_kcb(kcb2)
    hive_parser.add_kcb(kcb3)
    return hive_parser


class TestHiveParser():

    def test_add_kcb(self, hive_parser):
        kcb = dd({'initial_time': 0, 'index': 0, 'thread_id': 620,
                  'status': 0, 'key_handle': 18446735964879434920,
                  'key_name': '\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\WBEM\\WDM', 'process_id': 3820})
        hive_parser.add_kcb(kcb)
        assert kcb.key_handle in hive_parser.kcblocks

        kcblock = hive_parser.kcblocks[kcb.key_handle]
        assert isinstance(kcblock, Kcb)
        assert kcblock.key == kcb.key_name

    def test_remove_kcb(self, hive_parser):
        kcb = dd({'initial_time': 0, 'index': 0, 'thread_id': 620,
                  'status': 0, 'key_handle': 18446735964879434920,
                  'key_name': '\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\WBEM\\WDM', 'process_id': 3820})
        hive_parser.remove_kcb(kcb.key_handle)
        assert kcb.key_handle not in hive_parser.kcblocks

    @pytest.mark.parametrize('kevent_type', [REG_OPEN_KEY, REG_CREATE_KEY, REG_QUERY_KEY, REG_DELETE_KEY])
    def test_parse_hive_key_kevent_full_node_name(self, kevent_type, hive_parser, kevent_mock):
        regkevt = dd({"index": 0, "process_id": 1224, "status": 3221225524, "key_handle": 0,
                      "key_name": "\\Registry\\Machine\\Software\\Classes\\Applications\\Explorer.exe"
                                  "\\Drives\\C\\DefaultIcon", "thread_id": 2164, "initial_time": 24218563385})
        hive_parser.parse_hive(kevent_type, regkevt)
        kparams = kevent_mock.params

        assert kparams['hive'] == 'REGISTRY_MACHINE_SOFTWARE'
        assert kparams['key'] == 'SOFTWARE\\Classes\\Applications\\Explorer.exe\\Drives\\C\\DefaultIcon'
        assert kparams['status'] == regkevt.status
        assert kparams['pid'] == regkevt.process_id
        assert kparams['tid'] == regkevt.thread_id

    @pytest.mark.parametrize('kevent_type', [REG_OPEN_KEY, REG_CREATE_KEY, REG_QUERY_KEY, REG_DELETE_KEY])
    def test_parse_hive_key_kevent_kcb_lookup_match(self, kevent_type, hive_parser, kevent_mock):
        regkevt = dd({"index": 2, "process_id": 896, "status": 0, "key_handle": 18446735964812642928,
                      "key_name": "ThreadingModel", "thread_id": 2916, "initial_time": 24219715376})
        hive_parser.parse_hive(kevent_type, regkevt)
        kparams = kevent_mock.params

        assert kparams['hive'] == 'REGISTRY_MACHINE_SOFTWARE'
        assert kparams['key'] == 'SOFTWARE\\Classes\\CLSID\\{D2D588B5-D081-11D0-99E0-00C04FC2F8EC}' \
                                  '\\InprocServer32\\ThreadingModel'
        assert kparams['status'] == regkevt.status
        assert kparams['pid'] == regkevt.process_id
        assert kparams['tid'] == regkevt.thread_id

    def test_parse_hive_key_handles_lookup(self, hive_parser, kevent_mock, thread_registry_mock):
        regkevt = dd({"index": 0, "process_id": 896, "status": 3221225524,
                      "key_handle": 18446735964819421216,
                      "key_name": "Bags\\59\\Shell\\{5C4F28B5-F869-4E84-8E60-F11DB97C5CC7}",
                      "thread_id": 2916, "initial_time": 24219715717})
        hive_parser.parse_hive(REG_OPEN_KEY, regkevt)

        thread_registry_mock.get_thread.assert_called_with(regkevt.process_id)

        kcb = hive_parser.kcblocks[regkevt.key_handle]
        assert kcb and isinstance(kcb, Kcb)

        assert kcb.key == "\\REGISTRY\\USER\\S-1-5-21-2945379629-2233710143-2353048178-1000_CLASSES\\Local Settings" \
                          "\\Software\Microsoft\\Windows\\Shell\\Bags\\59" \
                          "\\Shell\\{5C4F28B5-F869-4E84-8E60-F11DB97C5CC7}"
        assert kevent_mock.params['hive'] == 'REGISTRY_USER_S-1-5-21-2945379629-2233710143-2353048178-1000_CLASSES'
        assert kevent_mock.params['key'] == "S-1-5-21-2945379629-2233710143-2353048178-1000_CLASSES\\Local Settings" \
                                            "\\Software\Microsoft\\Windows\\Shell\\Bags\\59" \
                                            "\\Shell\\{5C4F28B5-F869-4E84-8E60-F11DB97C5CC7}"

    def test_parse_hive_set_value_kevent_full_node_name(self, hive_parser, kevent_mock):
        regkevt = dd({"index": 0, "process_id": 1224, "status": 3221225524, "key_handle": 0,
                     "key_name": "\\Registry\\Machine\\Software\\Classes\\Applications\\Explorer.exe"
                     "\\Drives\\C\\DefaultIcon", "thread_id": 2164, "initial_time": 24218563385})
        with patch('fibratus.registry.HiveParser._query_value', return_value=('open', 'REG_SZ')) \
                as query_value_mock:
            hive_parser.parse_hive(REG_SET_VALUE, regkevt)
            kparams = kevent_mock.params
            query_value_mock.assert_called_with(HKEY_LOCAL_MACHINE,
                                                'SOFTWARE\\Classes\\Applications\\Explorer.exe\\Drives\\C',
                                                'DefaultIcon')

            assert kparams['hive'] == 'REGISTRY_MACHINE_SOFTWARE'
            assert kparams['key'] == 'SOFTWARE\\Classes\\Applications\\Explorer.exe\\Drives\\C\\DefaultIcon'
            assert kparams['status'] == regkevt.status
            assert kparams['pid'] == regkevt.process_id
            assert kparams['tid'] == regkevt.thread_id
            assert kparams['value_type'] == 'REG_SZ'
            assert kparams['value'] == 'open'

    def test_parse_hive_set_value_kevent_full_node_name(self, hive_parser, kevent_mock):
        regkevt = dd({"index": 0, "process_id": 1224, "status": 3221225524, "key_handle": 0,
                              "key_name": "\\REGISTRY\\USER\\S-1-5-21-2945379629-2233710143-2353048178-1000_CLASSES"
                              "\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\TrayNotify\\IconStreams",
                              "thread_id": 2164, "initial_time": 24218563385})
        with patch('fibratus.registry.HiveParser._query_value', return_value=('0x12', 'REG_DWORD')) \
                as query_value_mock:
            hive_parser.parse_hive(REG_QUERY_VALUE, regkevt)
            kparams = kevent_mock.params
            query_value_mock.assert_called_with(HKEY_USERS,
                                                    "S-1-5-21-2945379629-2233710143-2353048178-1000_CLASSES"
                                                    "\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion"
                                                    "\\TrayNotify",
                                                    'IconStreams')
            assert kparams['hive'] == 'REGISTRY_USER_S-1-5-21-2945379629-2233710143-2353048178-1000_CLASSES'
            assert kparams['key'] == "S-1-5-21-2945379629-2233710143-2353048178-1000_CLASSES\\Local Settings" \
                                     "\\Software\\Microsoft\\Windows\\CurrentVersion\\TrayNotify\\IconStreams"
            assert kparams['status'] == regkevt.status
            assert kparams['pid'] == regkevt.process_id
            assert kparams['tid'] == regkevt.thread_id
            assert kparams['value_type'] == 'REG_DWORD'
            assert kparams['value'] == '0x12'

    def test_parse_hive_delete_value(self, hive_parser, kevent_mock):
        regkevt = dd({"index": 0, "process_id": 1224, "status": 3221225524, "key_handle": 0,
                      "key_name": "\\Registry\\Machine\\Software\\Classes\\Applications\\Explorer.exe"
                                  "\\Drives\\C\\DefaultIcon", "thread_id": 2164, "initial_time": 24218563385})

        hive_parser.parse_hive(REG_DELETE_VALUE, regkevt)

        kparams = kevent_mock.params

        assert kparams['hive'] == 'REGISTRY_MACHINE_SOFTWARE'
        assert kparams['key'] == 'SOFTWARE\\Classes\\Applications\\Explorer.exe\\Drives\\C\\DefaultIcon'
        assert kparams['status'] == regkevt.status
        assert kparams['pid'] == regkevt.process_id
        assert kparams['tid'] == regkevt.thread_id

    def test_parse_hive_na(self, hive_parser, kevent_mock):
        regkevt = dd({"index": 2, "process_id": 896, "status": 0, "key_handle": 19446735964812642920,
                      "key_name": "ThreadingModel", "thread_id": 2916, "initial_time": 24219715376})
        hive_parser.parse_hive(REG_OPEN_KEY, regkevt)
        kparams = kevent_mock.params

        assert kparams['hive'] == NA
        assert kparams['key'] == '..\\ThreadingModel'



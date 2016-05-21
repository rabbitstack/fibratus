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
from unittest.mock import Mock

import pytest


from fibratus.common import DotD as dd, NA
from fibratus.fs import FsIO, FileOps
from fibratus.handle import HandleInfo, HandleType
from fibratus.kevent import KEvent
from fibratus.kevent_types import CREATE_FILE, DELETE_FILE, WRITE_FILE, RENAME_FILE
from fibratus.thread import ThreadRegistry


@pytest.fixture(scope='module')
def kevent():
    return KEvent(Mock(spec_set=ThreadRegistry))


@pytest.fixture(scope='module')
def fsio(kevent):
    handles = [HandleInfo(3080, 18446738026482168384, HandleType.DIRECTORY,
                          "\\Device\\HarddiskVolume2\\Users\\Nedo\\AppData\\Local\\VirtualStore", 640),
               HandleInfo(2010, 18446738023471035392, HandleType.FILE,
                          "\\Device\\HarddiskVolume2\\Windows\\system32\\rpcss.dll", 640)]
    fsio = FsIO(kevent, handles)
    fsio.file_pool[18446738026474426144] = '\\Device\\HarddiskVolume2\\fibratus.log'
    return fsio


class TestFsIO():

    def test_init_fsio(self, fsio):
        assert len(fsio.file_handles) == 2

    @pytest.mark.parametrize('expected_op, kfsio',
                             [(FileOps.SUPERSEDE, dd({"file_object": 18446738026482168384, "ttid": 1484,
                                                      "create_options": 1223456,
                                         "open_path": "\\Device\\HarddiskVolume2\\Windows\\system32\\kernel32.dll",
                                         "irp_ptr": 18446738026471032392, "share_access": 1, "file_attributes": 0})),
                              (FileOps.OPEN, dd({"file_object": 18446738026482168384, "ttid": 1484,
                                                 "create_options": 18874368,
                                         "open_path": "\\Device\\HarddiskVolume2\\Windows\\system32\\kernel32.dll",
                                         "irp_ptr": 18446738026471032392, "share_access": 2, "file_attributes": 0})),
                              (FileOps.CREATE, dd({"file_object": 18446738026482168384, "ttid": 1484,
                                                   "create_options": 33554532,
                                         "open_path": "\\Device\\HarddiskVolume2\\Windows\\system32\\kernel32.dll",
                                         "irp_ptr": 18446738026471032392, "share_access": 4, "file_attributes": 0})),
                              (FileOps.OPEN_IF, dd({"file_object": 18446738026482168384, "ttid": 1484,
                                                    "create_options": 58651617,
                                         "open_path": "\\Device\\HarddiskVolume2\\Windows\\system32\\kernel32.dll",
                                         "irp_ptr": 18446738026471032392, "share_access": 3, "file_attributes": 0})),
                              (FileOps.OVERWRITE, dd({"file_object": 18446738026482168384, "ttid": 1484,
                                                      "create_options": 78874400,
                                         "open_path": "\\Device\\HarddiskVolume2\\Windows\\system32\\kernel32.dll",
                                         "irp_ptr": 18446738026471032392, "share_access": 5, "file_attributes": 0})),
                              (FileOps.OVERWRITE_IF, dd({"file_object": 18446738026482168384, "ttid": 1484,
                                                         "create_options": 83886112,
                                         "open_path": "\\Device\\HarddiskVolume2\\Windows\\system32\\kernel32.dll",
                                         "irp_ptr": 18446738026471032392, "share_access": 6, "file_attributes": 0}))])
    def test_create_file_operation(self, expected_op, kfsio, fsio, kevent):

        fsio.parse_fsio(CREATE_FILE, kfsio)

        kparams = kevent.params
        assert kparams.file == kfsio.open_path
        assert kparams.tid == kfsio.ttid
        assert kparams.operation == expected_op.name

    @pytest.mark.parametrize('expected_share_mask, kfsio',
                             [('r--', dd({"file_object": 18446738026482168384, "ttid": 1484, "create_options": 18874368,
                                         "open_path": "\\Device\\HarddiskVolume2\\Windows\\system32\\kernel32.dll",
                                         "irp_ptr": 18446738026471032392, "share_access": 1, "file_attributes": 0})),
                              ('-w-', dd({"file_object": 18446738026482168384, "ttid": 1484, "create_options": 18874368,
                                         "open_path": "\\Device\\HarddiskVolume2\\Windows\\system32\\kernel32.dll",
                                         "irp_ptr": 18446738026471032392, "share_access": 2, "file_attributes": 0})),
                              ('--d', dd({"file_object": 18446738026482168384, "ttid": 1484, "create_options": 18874368,
                                         "open_path": "\\Device\\HarddiskVolume2\\Windows\\system32\\kernel32.dll",
                                         "irp_ptr": 18446738026471032392, "share_access": 4, "file_attributes": 0})),
                              ('rw-', dd({"file_object": 18446738026482168384, "ttid": 1484, "create_options": 18874368,
                                         "open_path": "\\Device\\HarddiskVolume2\\Windows\\system32\\kernel32.dll",
                                         "irp_ptr": 18446738026471032392, "share_access": 3, "file_attributes": 0})),
                              ('r-d', dd({"file_object": 18446738026482168384, "ttid": 1484, "create_options": 18874368,
                                         "open_path": "\\Device\\HarddiskVolume2\\Windows\\system32\\kernel32.dll",
                                         "irp_ptr": 18446738026471032392, "share_access": 5, "file_attributes": 0})),
                              ('-wd', dd({"file_object": 18446738026482168384, "ttid": 1484, "create_options": 18874368,
                                         "open_path": "\\Device\\HarddiskVolume2\\Windows\\system32\\kernel32.dll",
                                         "irp_ptr": 18446738026471032392, "share_access": 6, "file_attributes": 0})),
                              ('rwd', dd({"file_object": 18446738026482168384, "ttid": 1484, "create_options": 18874368,
                                         "open_path": "\\Device\\HarddiskVolume2\\Windows\\system32\\kernel32.dll",
                                         "irp_ptr": 18446738026471032392, "share_access": 7, "file_attributes": 0})),
                              ('---', dd({"file_object": 18446738026482168384, "ttid": 1484, "create_options": 18874368,
                                         "open_path": "\\Device\\HarddiskVolume2\\Windows\\system32\\kernel32.dll",
                                         "irp_ptr": 18446738026471032392, "share_access": -1, "file_attributes": 0}))])
    def test_create_file_share_mask(self, expected_share_mask, kfsio, fsio, kevent):
        fsio.parse_fsio(CREATE_FILE, kfsio)
        assert kevent.params.share_mask == expected_share_mask

    def test_delete_file(self, fsio, kevent):
        kfsio = dd({"file_object": 18446738026474426144, "ttid": 1956, "irp_ptr": 18446738026471032392})
        fsio.parse_fsio(DELETE_FILE, kfsio)
        assert kevent.params.tid == kfsio.ttid
        assert kevent.params.file == '\\Device\\HarddiskVolume2\\fibratus.log'

    def test_write_file(self, fsio, kevent):
        kfsio = dd({"file_object": 18446738026474426144, "io_flags": 0, "io_size": 8296, "offset": 75279, "ttid": 1956})
        fsio.parse_fsio(WRITE_FILE, kfsio)
        assert kevent.params.tid == kfsio.ttid
        assert kevent.params.file == NA
        assert kevent.params.io_size == kfsio.io_size / 1024

    def test_rename_file(self, fsio, kevent):
        kfsio = dd({"file_object": 18446738023471035392, "ttid": 1956, "irp_ptr": 18446738026471032392})
        fsio.parse_fsio(RENAME_FILE, kfsio)
        assert kevent.params.tid == kfsio.ttid
        assert kevent.params.file == '\\Device\\HarddiskVolume2\\Windows\\system32\\rpcss.dll'
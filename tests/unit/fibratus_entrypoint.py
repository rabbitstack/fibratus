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
import pytest

from unittest.mock import Mock
from fibratus.apidefs.etw import KERNEL_LOGGER_NAME
from fibratus.controller import KTraceController, KTraceProps
from fibratus.dll import DllRepository
from fibratus.fibratus_entrypoint import Fibratus
from fibratus.fs import FsIO
from fibratus.handle import HandleRepository
from fibratus.kevent import KEvent
from fibratus.registry import HiveParser
from fibratus.tcpip import TcpIpParser
from fibratus.thread import ThreadRegistry
from kstream.kstreamc import KEventStreamCollector


@pytest.fixture(scope='module')
def kcontroller_mock():
    return Mock(spec_set=KTraceController)


@pytest.fixture(scope='module')
def fibratus(kcontroller_mock):
    f = Fibratus(None)
    f.kevt_streamc = Mock(spec_set=KEventStreamCollector)
    f.kcontroller = kcontroller_mock
    f.ktrace_props = Mock(spec_set=KTraceProps)
    f.handle_repository = Mock(spec_set=HandleRepository)
    f.thread_registry = Mock(spec_set=ThreadRegistry)
    f.kevent = Mock(spec_set=KEvent)
    f.fsio = Mock(spec_set=FsIO)
    f.hive_parser = Mock(spec_set=HiveParser)
    f.tcpip_parser = Mock(spec_set=TcpIpParser)
    f.dll_repository = Mock(spec_set=DllRepository)
    return f


class TestFibratus:

    def test_run(self, fibratus, kcontroller_mock):
        pass
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
from fibratus.kevent_types import *


@pytest.mark.parametrize('name, expected_kevent',
                         [(KEvents.CREATE_PROCESS, CREATE_PROCESS),
                         (KEvents.TERMINATE_PROCESS, TERMINATE_PROCESS),
                         (KEvents.CREATE_THREAD, CREATE_THREAD),
                         (KEvents.TERMINATE_THREAD, TERMINATE_THREAD),
                         (KEvents.REG_SET_VALUE, REG_SET_VALUE),
                         (KEvents.REG_QUERY_KEY, REG_QUERY_KEY),
                         (KEvents.REG_OPEN_KEY, REG_OPEN_KEY),
                         (KEvents.REG_QUERY_VALUE, REG_QUERY_VALUE),
                         (KEvents.REG_DELETE_KEY, REG_DELETE_KEY),
                         (KEvents.REG_DELETE_VALUE, REG_DELETE_VALUE),
                         (KEvents.REG_CREATE_KEY, REG_CREATE_KEY),
                         (KEvents.SEND, [SEND_SOCKET_UDPV4, SEND_SOCKET_TCPV4])])
def test_kname_to_tuple(name, expected_kevent):
    assert kname_to_tuple(name) == expected_kevent


def test_kname_to_tuple_unknown_kevent():
    with pytest.raises(UnknownKeventTypeError):
        kname_to_tuple('Exec')


def test_ktuple_to_name():
    pass
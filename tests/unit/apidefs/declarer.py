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
from ctypes import c_uint
import os

import fibratus.apidefs.declarer as declarer


class TestDeclarer():

    def test_declare_function(self):
        get_current_process_id = declarer.declare(declarer.KERNEL, 'GetCurrentProcessId', [], c_uint)

        assert callable(get_current_process_id)
        assert get_current_process_id.restype == c_uint
        assert get_current_process_id.argtypes is None

        # check the function result
        pid = os.getpid()
        assert get_current_process_id() == pid
# Copyright 2017 by Nedim Sabic (RabbitStack)
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
from io import TextIOBase

from fibratus.output.fs import FsOutput
from unittest.mock import patch, Mock
import time
import os
import json


class TestFsOutput(object):

    def test_init(self):
        with patch('io.open', return_value=Mock(spec_set=TextIOBase)) as stream_mock:
            fs_output = FsOutput(path='C:\\', mode='a', format='json')
            filename = os.path.join(fs_output.path, '%s.fibra' % time.strftime('%x').replace('/', '-'))
            stream_mock.assert_called_with(filename, 'a')
            assert 'C:\\' in fs_output.path
            assert 'a' in fs_output.mode
            assert 'json' in fs_output.format

    def test_emit(self):
        with patch('io.open', return_value=Mock(spec_set=TextIOBase)):
            fs_output = FsOutput(path='C:\\', mode='a', format='json')
            body = {'kevent_type': 'CreateProcess'}
            fs_output.emit(body)
            fs_output.stream.write.assert_called_with(json.dumps(body) + '\n')
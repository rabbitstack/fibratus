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
from unittest.mock import Mock, patch, MagicMock

from fibratus.kevent import KEvent
from logbook import Logger
import pytest
import os

from fibratus.errors import BindingError
from fibratus.output.amqp import AmqpOutput
from fibratus.thread import ThreadInfo


@pytest.fixture(scope='module')
def outputs():
    return dict(amqp=Mock(spec_set=AmqpOutput))


class TestYaraBinding(object):

    def test_init(self, outputs):
        with patch.dict('sys.modules', **{
            'yara': MagicMock(),
        }):
            from fibratus.binding.yar import YaraBinding
            with patch('os.path.exists', return_value=True), \
                 patch('os.path.isdir', return_value=True), \
                 patch('glob.glob', return_value=['silent_banker.yar']), \
                 patch('yara.compile') as yara_compile_mock:
                    YaraBinding(outputs,
                                Mock(spec_set=Logger), output='amqp', path='C:\\yara-rules')
                    yara_compile_mock.assert_called_with(os.path.join('C:\\yara-rules', 'silent_banker.yar'))

    def test_init_invalid_path(self, outputs):
        with patch.dict('sys.modules', **{
            'yara': None,
        }):
            from fibratus.binding.yar import YaraBinding
            with patch('os.path.exists', return_value=False), \
                 patch('os.path.isdir', return_value=False):
                    with pytest.raises(BindingError) as e:
                        YaraBinding(outputs,
                                    Mock(spec_set=Logger), output='amqp', path='C:\\yara-rules-invalid')
                        assert 'C:\\yara-rules-invalid rules path does not exist' in str(e.value)

    def test_init_yara_python_not_installed(self, outputs):
        with patch.dict('sys.modules', **{
            'yara': None,
        }):
            from fibratus.binding.yar import YaraBinding
            with pytest.raises(BindingError) as e:
                YaraBinding(outputs,
                            Mock(spec_set=Logger), output='amqp', path='C:\\yara-rules')
                assert 'yara-python package is not installed' in str(e.value)

    def test_run(self, outputs):
        with patch.dict('sys.modules', **{
            'yara': MagicMock(),
        }):
            from fibratus.binding.yar import YaraBinding
            with patch('os.path.exists', return_value=True), \
                 patch('os.path.isdir', return_value=True), \
                 patch('glob.glob', return_value=['silent_banker.yar']), \
                 patch('yara.compile'):
                yara_binding = YaraBinding(outputs,
                                           Mock(spec_set=Logger), output='amqp', path='C:\\yara-rules')
                yara_binding.run(thread_info=Mock(spec_set=ThreadInfo), kevent=Mock(spec_set=KEvent))
                assert yara_binding._rules.match.called

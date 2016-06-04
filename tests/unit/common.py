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

from mock import patch
from fibratus.common import IO


class TestIO(object):

    @patch('fibratus.common.write_console_unicode')
    @patch('fibratus.common.byref', return_value=8)
    def test_write_console_new_line(self, byref_mock,  write_console_unicode_mock):
        IO._stdout_handle = 10
        IO.write_console('Fibratus')
        write_console_unicode_mock.assert_called_with(10, 'Fibratus\n', 9, 8, None)

    @patch('fibratus.common.write_console_unicode')
    @patch('fibratus.common.byref', return_value=8)
    def test_write_console_same_line(self, byref_mock, write_console_unicode_mock):
        IO._stdout_handle = 10
        IO.write_console('Fibratus', False)
        write_console_unicode_mock.assert_called_with(10, 'Fibratus\r', 9, 8, None)

    def test_write_console_unicode(self):
        IO.write_console('aaaàçççñññ skräms inför på fédéra')

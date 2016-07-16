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
from unittest.mock import patch

import pytest

from fibratus.apidefs.sys import STD_OUTPUT_HANDLE, GENERIC_READ, GENERIC_WRITE, \
    FILE_SHARE_READ, CONSOLE_TEXTMODE_BUFFER, FILE_SHARE_WRITE, INVALID_HANDLE_VALUE, COORD, SMALL_RECT, CHAR_INFO, \
    CONSOLE_SCREEN_BUFFER_INFO
from fibratus.errors import TermInitializationError
from fibratus.term import AnsiTerm


class TestAnsiTerm(object):

    @patch('fibratus.term.get_std_handle', return_value=1)
    @patch('fibratus.term.get_console_screen_buffer_info')
    @patch('fibratus.term.get_console_cursor_info')
    @patch('fibratus.term.create_console_screen_buffer', return_value=2)
    @patch('fibratus.term.set_console_cursor_info')
    @patch('fibratus.term.set_console_active_screen_buffer')
    def test_setup_console(self, set_console_active_screen_buffer_mock,
                           set_console_cursor_info_mock,
                           create_console_screen_buffer_mock,
                           get_console_cursor_info_mock,
                           get_console_screen_buffer_info_mock,
                           get_std_handle_mock):

        with patch('fibratus.term.byref', side_effect=[1, 2, 3]):
            ansi_term = AnsiTerm()
            assert not ansi_term.term_ready
            ansi_term.setup_console()

            get_std_handle_mock.assert_called_with(STD_OUTPUT_HANDLE)
            get_console_screen_buffer_info_mock.assert_called_with(1, 1)
            get_console_cursor_info_mock.assert_called_with(1, 2)

            create_console_screen_buffer_mock.assert_called_with(GENERIC_READ | GENERIC_WRITE,
                                                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                                                 None,
                                                                 CONSOLE_TEXTMODE_BUFFER,
                                                                 None)

            set_console_cursor_info_mock.assert_called_with(2, 3)
            set_console_active_screen_buffer_mock.assert_called_with(2)

            assert ansi_term.term_ready

    @patch('fibratus.term.get_std_handle', return_value=INVALID_HANDLE_VALUE)
    def test_setup_console_invalid_std_console(self, get_std_handle_mock):

            ansi_term = AnsiTerm()
            with pytest.raises(TermInitializationError):
                ansi_term.setup_console()
                get_std_handle_mock.assert_called_with(STD_OUTPUT_HANDLE)

            assert not ansi_term.term_ready

    @patch('fibratus.term.get_std_handle', return_value=1)
    @patch('fibratus.term.get_console_screen_buffer_info')
    @patch('fibratus.term.get_console_cursor_info')
    @patch('fibratus.term.create_console_screen_buffer', return_value=INVALID_HANDLE_VALUE)
    def test_setup_console_invalid_frame_buffer(self, create_console_screen_buffer_mock,
                                                get_console_cursor_info_mock,
                                                get_console_screen_buffer_info_mock,
                                                get_std_handle_mock):

            ansi_term = AnsiTerm()
            with pytest.raises(TermInitializationError):
                ansi_term.setup_console()
                create_console_screen_buffer_mock.assert_called_with(GENERIC_READ | GENERIC_WRITE,
                                                                     FILE_SHARE_READ | FILE_SHARE_WRITE,
                                                                     None,
                                                                     CONSOLE_TEXTMODE_BUFFER,
                                                                     None)

            assert not ansi_term.term_ready

    @patch('fibratus.term.get_std_handle', return_value=1)
    @patch('fibratus.term.get_console_screen_buffer_info')
    @patch('fibratus.term.get_console_cursor_info')
    @patch('fibratus.term.create_console_screen_buffer', return_value=2)
    @patch('fibratus.term.set_console_cursor_info')
    @patch('fibratus.term.set_console_active_screen_buffer')
    def test_restore_console(self, set_console_active_screen_buffer_mock,
                             set_console_cursor_info_mock,
                             create_console_screen_buffer_mock,
                             get_console_cursor_info_mock,
                             get_console_screen_buffer_info_mock,
                             get_std_handle_mock):

        ansi_term = AnsiTerm()
        ansi_term.setup_console()
        assert ansi_term.term_ready
        with patch('fibratus.term.byref', return_value=2):
            ansi_term.restore_console()
            set_console_active_screen_buffer_mock.assert_called_with(1)
            assert not ansi_term.term_ready
            set_console_cursor_info_mock.assert_called_with(1, 2)

    @patch('fibratus.term.get_std_handle', return_value=1)
    @patch('fibratus.term.get_console_screen_buffer_info')
    @patch('fibratus.term.get_console_cursor_info')
    @patch('fibratus.term.create_console_screen_buffer', return_value=2)
    @patch('fibratus.term.set_console_cursor_info')
    @patch('fibratus.term.set_console_active_screen_buffer')
    @patch('fibratus.term.write_console_output')
    def test_write_output(self, write_console_output_mock,
                          set_console_active_screen_buffer_mock,
                          set_console_cursor_info_mock,
                          create_console_screen_buffer_mock,
                          get_console_cursor_info_mock,
                          get_console_screen_buffer_info_mock,
                          get_std_handle_mock):
        ansi_term = AnsiTerm()

        buffer_info = CONSOLE_SCREEN_BUFFER_INFO()
        buffer_info.size.x = 200
        buffer_info.size.y = 300

        with patch.object(CONSOLE_SCREEN_BUFFER_INFO, '__new__', return_value=buffer_info):
            ansi_term.setup_console()
            ansi_term.write_output('Top inbound packets\n')
            write_console_output_mock.assert_called_once()



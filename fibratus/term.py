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
from _ctypes import byref

from fibratus.apidefs.sys import CONSOLE_SCREEN_BUFFER_INFO, INVALID_HANDLE_VALUE, get_std_handle, STD_OUTPUT_HANDLE, \
    create_console_screen_buffer, GENERIC_READ, GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, \
    CONSOLE_TEXTMODE_BUFFER, get_console_screen_buffer_info, COORD, SMALL_RECT, CHAR_INFO, \
    set_console_active_screen_buffer, write_console_output, CURSOR_INFO, get_console_cursor_info, \
    set_console_cursor_info
from fibratus.errors import TermInitializationError


HIGH_INTENSITY = 0x0008

# terminal colors
BLACK = 0x0000
DARK_BLUE = 0x0001
DARK_GREEN = 0x0002
DARK_RED = 0x0004
GRAY = DARK_BLUE | DARK_GREEN | DARK_RED
DARK_YELLOW = DARK_RED | DARK_GREEN
DARK_PURPLE = DARK_RED | DARK_BLUE
DARK_CYAN = DARK_GREEN | DARK_BLUE
LIGHT_WHITE = GRAY | HIGH_INTENSITY


class AnsiTerm():
    """Terminal's low level interface.

    Provides a set of methods to interact
    with the Windows terminals.
    """

    def __init__(self):
        self.backbuffer_info = CONSOLE_SCREEN_BUFFER_INFO()
        self.cursor_info = CURSOR_INFO()
        self.cols = 0
        self.rows = 0
        self.console_handle = INVALID_HANDLE_VALUE
        self.backbuffer_handle = INVALID_HANDLE_VALUE
        self.rect = None
        self.char_buffer = None
        self.coord = COORD(0, 0)
        self.size = COORD(0, 0)

    def init_console(self):
        self.console_handle = get_std_handle(STD_OUTPUT_HANDLE)
        if self.console_handle == INVALID_HANDLE_VALUE:
            raise TermInitializationError()

        get_console_screen_buffer_info(self.console_handle, byref(self.backbuffer_info))
        get_console_cursor_info(self.console_handle, byref(self.cursor_info))
        self._show_cursor(False)

        self.cols = self.backbuffer_info.size.x
        self.rows = self.backbuffer_info.size.y
        self.size = COORD(self.cols, self.rows)
        self.rect = SMALL_RECT(0, 0, self.cols - 1, self.rows - 1)

        self.char_buffer = (CHAR_INFO * (self.size.x * self.size.y))()

        self.backbuffer_handle = create_console_screen_buffer(GENERIC_READ | GENERIC_WRITE,
                                                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                                                              None,
                                                              CONSOLE_TEXTMODE_BUFFER,
                                                              None)
        if self.backbuffer_handle == INVALID_HANDLE_VALUE:
            raise TermInitializationError()
        set_console_active_screen_buffer(self.backbuffer_handle)

    def restore_console(self):
        if self.console_handle:
            self._show_cursor(True)
            set_console_active_screen_buffer(self.console_handle)

    def write(self, char_seq):
        col = 0
        index = 0
        line_feed = False

        for char in char_seq:
            if char == '\n':
                line_feed = True
            col += 1
            if col == self.cols:
                col = 0
                if line_feed:
                    line_feed = False
                    continue

            if line_feed:
                line_feed = False
                blank_index = col
                while blank_index <= self.cols:
                    self.char_buffer[blank_index - 1].char.unicode_char = ' '
                    blank_index += 1
                    index += 1
                col = 0
                continue

            self.char_buffer[index].char.unicode_char = char
            self.char_buffer[index].attributes = LIGHT_WHITE
            index += 1

        write_console_output(self.backbuffer_handle,
                             self.char_buffer,
                             self.size,
                             self.coord,
                             byref(self.rect))

    def cls(self):
        for y in range(self.rows):
            for x in range(self.cols):
                i = (y * self.cols) + x
                self.char_buffer[i].char.unicode_char = ' '
        write_console_output(self.backbuffer_handle,
                             self.char_buffer,
                             self.coord,
                             self.size,
                             byref(self.rect))

    def _show_cursor(self, visible=True):
        self.cursor_info.visible = visible
        set_console_cursor_info(self.console_handle, byref(self.cursor_info))
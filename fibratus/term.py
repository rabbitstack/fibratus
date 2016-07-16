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
from ctypes import c_ulong

from fibratus.apidefs.sys import CONSOLE_SCREEN_BUFFER_INFO, INVALID_HANDLE_VALUE, get_std_handle, STD_OUTPUT_HANDLE, \
    create_console_screen_buffer, GENERIC_READ, GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, \
    CONSOLE_TEXTMODE_BUFFER, get_console_screen_buffer_info, COORD, SMALL_RECT, CHAR_INFO, \
    set_console_active_screen_buffer, write_console_output, CURSOR_INFO, get_console_cursor_info, \
    set_console_cursor_info, write_console_unicode
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


class AnsiTerm(object):
    """Terminal's low level interface.

    Provides a set of methods to interact
    with the Windows terminals. By writing the chars
    directly to the screen buffer can prevent the
    annoying screen flickering.
    """

    def __init__(self):
        """Creates a new instance of the terminal.
        """
        self._cursor_info = CURSOR_INFO()
        self._console = INVALID_HANDLE_VALUE
        self._framebuffer = INVALID_HANDLE_VALUE
        self._char_buffer = None
        self._cols = 0
        self._rows = 0
        self._rect = None
        self._coord = COORD(0, 0)
        self._size = COORD(0, 0)
        self._term_ready = False

    def setup_console(self):
        """Initializes the screen frame buffer.

        Swaps the current screen buffer with a
        brand new created back buffer where the
        characters can be written to the flicker-free
        rectangular region.

        """
        self._console = get_std_handle(STD_OUTPUT_HANDLE)
        # could not get the standard
        # console handle, raise an exception
        if self._console == INVALID_HANDLE_VALUE:
            raise TermInitializationError()

        buffer_info = CONSOLE_SCREEN_BUFFER_INFO()
        get_console_screen_buffer_info(self._console, byref(buffer_info))
        get_console_cursor_info(self._console, byref(self._cursor_info))
        self._cursor_info.visible = False

        self._cols = buffer_info.size.x
        self._rows = buffer_info.size.y
        self._size = COORD(self._cols, self._rows)
        self._rect = SMALL_RECT(0, 0, self._cols - 1, self._rows - 1)
        self._char_buffer = (CHAR_INFO * (self._size.x * self._size.y))()
        self._framebuffer = create_console_screen_buffer(GENERIC_READ | GENERIC_WRITE,
                                                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                                                         None,
                                                         CONSOLE_TEXTMODE_BUFFER,
                                                         None)
        if self._framebuffer == INVALID_HANDLE_VALUE:
            raise TermInitializationError()
        # hide the cursor and swap
        # the console active screen buffer
        set_console_cursor_info(self._framebuffer, byref(self._cursor_info))
        set_console_active_screen_buffer(self._framebuffer)

        self._term_ready = True

    def restore_console(self):
        if self._console:
            set_console_active_screen_buffer(self._console)
            self._cursor_info.visible = True
            self._term_ready = False
            set_console_cursor_info(self._console,
                                    byref(self._cursor_info))

    def write_output(self, charseq, color=LIGHT_WHITE):
        """Writes character and color attribute data to the frame buffer.

        The data to be written is taken from a correspondingly sized rectangular
        block at a specified location in the source buffer.

        Parameters
        ----------

        charseq: str
            the sequence of characters to be written on the frame buffer

        color: int
            the terminal output color
        """
        col = 0
        x = 0
        crlf = False

        for char in charseq:
            if char == '\n':
                crlf = True
            col += 1
            # the last column has been reached.
            # If there was a carriage return
            # then stop the iteration
            if col == self._cols:
                col = 0
                if crlf:
                    crlf = False
                    continue

            if crlf:
                crlf = False
                space = col
                # keep filling the rectangle with spaces
                # until we reach the last column
                while space <= self._cols:
                    self._char_buffer[space - 1].char.unicode_char = ' '
                    space += 1
                    x += 1
                # reset the column and
                # stop the current iteration
                col = 0
                continue
            self._char_buffer[x].char.unicode_char = char
            self._char_buffer[x].attributes = color

            x += 1
        # write the character attribute data
        # to the screen buffer
        write_console_output(self._framebuffer,
                             self._char_buffer,
                             self._size,
                             self._coord,
                             byref(self._rect))

    def write_console(self, charseq):
        """Writes a string to a console frame buffer
        beginning at the current cursor location.

        charseq: str
            the string to be written on the frame buffer
        """
        write_console_unicode(self._framebuffer, charseq, len(charseq), byref(c_ulong()), None)

    def cls(self):
        """Clears the current screen buffer.
        """
        for y in range(self._rows):
            for x in range(self._cols):
                i = (y * self._cols) + x
                self._char_buffer[i].char.unicode_char = ' '
        write_console_output(self._framebuffer,
                             self._char_buffer,
                             self._coord,
                             self._size,
                             byref(self._rect))

    @property
    def term_ready(self):
        return self._term_ready


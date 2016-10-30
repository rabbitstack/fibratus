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
from fibratus.apidefs.sys import write_console_unicode, get_std_handle, STD_OUTPUT_HANDLE, close_handle

NA = '<NA>'


class DotD(dict):
    """This code is borrowed from easydict
    Credits to:

    https://github.com/makinacorpus/easydict/blob/master/easydict/__init__.py
    """
    def __init__(self, d=None, **kwargs):
        if d is None:
            d = {}
        if kwargs:
            d.update(**kwargs)
        for k, v in d.items():
            setattr(self, k, v)
        # class attributes
        for k in self.__class__.__dict__.keys():
            if not (k.startswith('__') and k.endswith('__')):
                setattr(self, k, getattr(self, k))

    def __setattr__(self, name, value):
        if isinstance(value, (list, tuple)):
            value = [self.__class__(x)
                     if isinstance(x, dict) else x for x in value]
        else:
            value = self.__class__(value) if isinstance(value, dict) else value
        super(DotD, self).__setattr__(name, value)
        super(DotD, self).__setitem__(name, value)

    __setitem__ = __setattr__


class IO(object):

    _stdout_handle = get_std_handle(STD_OUTPUT_HANDLE)
    assert _stdout_handle, 'could not acquire the standard output stream handle'

    @classmethod
    def write_console(cls, charseq, new_line=True):
        """Outputs to a Windows console using UNICODE charset.

        Parameters
        ----------

        charseq: str
            the sequence of characters to be written

        new_line: bool
            indicates if the output should be written on the new line
        """
        if new_line:
            charseq += '\n'
        else:
            charseq += '\r'
        write_console_unicode(cls._stdout_handle, charseq, len(charseq), byref(c_ulong()), None)

    def __del__(self):
        if self._stdout_handle:
            close_handle(self._stdout_handle)

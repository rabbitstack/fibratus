# Copyright 2015 by Nedim Sabic (RabbitStack)
# All Rights Reserved.
# http://rabbitstack.github.io
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

from ctypes import windll, CDLL


ADVAPI = 0
KERNEL = 1
NT = 2
C = 3
USER = 4

__LIBS__ = {ADVAPI: windll.advapi32,
            KERNEL: windll.kernel32,
            NT: windll.ntdll,
            C: CDLL('msvcrt'),
            USER: windll.user32}


def declare(lib_name, function_name, args, restype):
    if lib_name in __LIBS__:
        lib = __LIBS__[lib_name]
        # declare the function and set
        # the argument types
        function = getattr(lib, function_name)
        if function:
            if len(args) > 0:
                function.argtypes = args
            if restype:
                function.restype = restype
        return function
    else:
        raise AttributeError('The library %s cannot be loaded' % lib_name)

# Copyright 2016 by Nedim Sabic (RabbitStack)
# http://rabbitstack.github.io
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

from kstream.includes.windows cimport *

cdef inline SYSTEMTIME sys_time(LARGE_INTEGER timestamp) nogil:
    cdef FILETIME f
    cdef SYSTEMTIME s
    cdef SYSTEMTIME tzt

    f.high_date = timestamp.high
    f.low_date = timestamp.low
    filetime_to_systemtime(&f, &s)
    systemtime_to_tz_specific_localtime(NULL, &s, &tzt)

    return tzt
# Copyright 2016 by Nedim Sabic (RabbitStack)
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

"""
Shows top registry keys by I/O activity.
"""

import collections

keys = collections.Counter()


def on_init():
    interval(1)
    columns(['Key', '#Ops'])
    sort_by('#Ops')


def on_next_kevent(Event):
    pass


def on_interval():
    keys.update(("HKLM\\SYSTEM\\ControlSet001\\Services\\WinSock2\\Parameters\\Protocol_Catalog9",))
    keys.update(("HKLM\\SYSTEM\\ControlSet001\\Services\\WinSock2\\Parameters\\Protocol_Catalog9",))
    keys.update(("HKLM\\SYSTEM\\ControlSet001\\Services\\WinSock2\\Parameters\\Protocol_Catalog9",))
    keys.update(("HKLM\\SYSTEM\\ControlSet001\\Control\\Nls\\Sorting\\Ids",))
    for key, count in keys.items():
        add_row([key, count])
    render_table()
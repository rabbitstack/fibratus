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
Shows top processes by registry I/O activity.
"""

import collections

processes_registry_io = collections.Counter()


def on_init():
    set_filter('RegOpenKey', 'RegQueryKey', 'RegCreateKey', 'RegQueryValue', 'RegSetValue', 'RegDeleteValue')
    columns(["Process", "#Ops"])
    sort_by('#Ops')
    set_interval(1)
    limit(20)


def on_next_kevent(kevent):
    process = ['%s (%d)' % (kevent.thread.name, kevent.thread.pid)]
    processes_registry_io.update(process)


def on_interval():
    for process, io in processes_registry_io.items():
        add_row([process, io])
    render_tabular()

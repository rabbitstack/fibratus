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

"""
Shows top TCP / UDP connections
"""

import collections

connections = collections.Counter()


def on_init():
    set_filter('Send')
    columns(["Port", "IP", "Count"])
    sort_by('Count')


def on_next_kevent(kevent):
    connections.update((kevent.params.dport, kevent.params.ip_dst))

    for t, count in connections.items():
        add_row([t[0], t[1], count])

    render_tabular()


def on_stop():
    pass

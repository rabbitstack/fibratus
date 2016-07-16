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
Shows the top TCP / UDP incoming packets.
"""

import collections

connections = collections.Counter()


def on_init():
    set_filter('Recv')
    columns(["Source", "Count"])
    sort_by('Count')
    set_interval(1)
    title('Top incoming TCP/UDP packets')


def on_next_kevent(kevent):
    src = ['%s:%d' % (kevent.params.ip_dst, kevent.params.dport)]
    connections.update(src)


def on_interval():
    for ip, count in connections.items():
        add_row([ip, count])
    render_tabular()


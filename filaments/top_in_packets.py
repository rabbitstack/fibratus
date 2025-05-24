# Copyright 2019-2020 by Nedim Sabic (RabbitStack)
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
Shows the top TCP / UDP inbound packets by IP/port tuple
"""

import collections
from utils.dotdict import dotdictify

__connections__ = collections.Counter()


def on_init():
    set_filter("evt.name = 'Recv'")
    columns(["Source", "Count"])
    sort_by('Count')
    interval(1)


@dotdictify
def on_next_event(event):
    src = ['%s:%d' % (event.params.sip, event.params.sport)]
    __connections__.update(src)


def on_interval():
    for ip, count in __connections__.copy().items():
        add_row([ip, count])
    render_table()
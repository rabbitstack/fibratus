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
Shows top keys by number of registry operations
"""

import collections
from utils.dotdict import dotdictify

__keys__ = collections.Counter()


def on_init():
    kfilter("kevt.category = 'registry'")
    columns(["Key", "#Ops"])
    sort_by('#Ops')
    interval(1)


@dotdictify
def on_next_kevent(kevent):
    key = kevent.kparams.key_name
    if key:
        __keys__.update((key, ))


def on_interval():
    for key, count in __keys__.copy().items():
        add_row([key, count])
    render_table()
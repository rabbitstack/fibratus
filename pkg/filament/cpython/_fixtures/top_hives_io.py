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
Shows top registry hives by I/O activity.
"""

import collections

hives = collections.Counter()


def on_init():
    set_interval(2)
    print("on_init")
    #set_filter('RegOpenKey or proc.name=java')
    #columns(["Hive", "#Ops"])
    #sort_by('#Ops')
    #set_interval(1)


def on_next_kevent(kevent):
    print("KEVENT\n", kevent["kparams"])
    #raise Exception('eggs', 'eggs')

def on_interval():
    for hive, count in hives.items():
        add_row([hive, count])
    render_tabular()

def sum(v):
    return 1 + 1
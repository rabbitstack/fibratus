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
Tests the on_next_event function.
"""

events = []

def on_init():
    interval(1)
    columns(['Key', '#Seq'])
    sort_by('#Seq')

def on_next_event(event):
    events.append({'key_name': event['params']['key_name'], 'seq': event['seq'], 'dip': event['params']['dip']})

def on_interval():
    for key in events:
        add_row([key['key_name'], key['seq']])
    render_table()

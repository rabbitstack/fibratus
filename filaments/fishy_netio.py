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
Anomalous process attempts to make a network request or it accepts an inbound connection
"""

from utils.dotdict import dotdictify

__pids__ = []
__procs__ = [
    'calc.exe',
    'notepad.exe',
    'mspaint.exe',
]


def on_init():
    kfilter("kevt.category = 'net' and ps.name in (%s)" % (', '.join([f'\'{ps}\'' for ps in __procs__])))


@dotdictify
def on_next_kevent(kevent):
    print(kevent)
    notify = True if kevent.pid in __pids__ else False
    if not notify:
        emit_alert(
            f'Anomalous network I/O detected to {kevent.kparams.dip}:{kevent.kparams.dport}',
            text(kevent),
            severity='critical',
            tags=['anomalous netio']
        )
        __pids__.append(kevent.pid)


def text(kevent):
    return """
        
        Source IP:        %s
        Source port:      %s
        Destination IP:   %s  
        Destination port: %s
        Protocol:         %s

        Process ==================================================================================

        Name: %s
        Comm: %s
        Cwd:  %s
        User: %s

        """ % (
        kevent.kparams.sip,
        kevent.kparams.sport,
        kevent.kparams.dip,
        kevent.kparams.dport,
        kevent.kparams.dport_name,
        kevent.exe,
        kevent.comm,
        kevent.cwd, kevent.sid)

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
Surfaces registry operations that would allow a process to execute on system startup
"""

import os
from utils.dotdict import dotdictify

__keys__ = [
    r'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run',
    r'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run',
    r'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    r'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    r'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices',
    r'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices',

    r'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon',
    r'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce',

    r'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Debug',
    r'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Debug',

    r'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce',

    r'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\0001',
    r'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend'
]

WINLOGON_KEY = r'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'


def on_init():
    kfilter("kevt.name = 'RegSetValue'")


@dotdictify
def on_next_kevent(kevent):
    key = os.path.dirname(kevent.kparams.key_name)

    # We check if the value being modified under the Winlogon key is Userinit.
    # The Userinit registry value defines which programs are run by Winlogon
    # when a user logs in to the system. Typically, Winlogon runs Userinit.exe,
    # which in turn runs logon scripts, reestablishes network connections,
    # and then starts explorer. Attackers can prepend the userinit.exe executable
    # with their own malicious binary/script.
    if key.lower() == WINLOGON_KEY.lower() and os.path.basename(kevent.kparams.key_name) != 'Userinit':
        return

    if any(k.lower() == key.lower() for k in __keys__):
        emit_alert(
                f'Registry persistence gained via {kevent.kparams.key_name}',
                text(kevent),
                severity='medium',
                tags=['registry persistence']
        )


def text(kevent):
    return """

        Key content: %s
        Key type:    %s
        
        Process ==================================================================================
        
        Name: %s
        Comm: %s
        Cwd:  %s
        User: %s
        
        """ % (
        kevent.kparams.value,
        kevent.kparams.type,
        kevent.exe,
        kevent.comm,
        kevent.cwd, kevent.sid)

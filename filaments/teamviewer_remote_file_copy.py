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
Identifies an executable or script file remotely downloaded via a TeamViewer transfer session
"""

from utils.dotdict import dotdictify

__author__ = 'Nedim Sabic Sabic'
__tags__ = ['Command and Control', 'TeamViewer']
__references__ = ['https://blog.menasec.net/2019/11/hunting-for-suspicious-use-of.html']
__severity__ = 'medium'

__catalog__ = {
    'framework':        'MITRE ATT&CK',
    'technique_id':     'T1105',
    'technique_name':   'Ingress Tool Transfer',
    'technique_ref':    'https://attack.mitre.org/techniques/T1105/',
    'tactic_id':        'TA0011',
    'tactic_name':      'Command and Control',
    'tactic_ref':       'https://attack.mitre.org/tactics/TA0011/'
}


extensions = [
    '.exe',
    '.dll',
    '.scr',
    '.com',
    '.bar',
    '.ps1',
    '.vbs',
    '.vbe',
    '.js',
    '.wsh',
    '.hta'
]


def on_init():
    kfilter("kevt.name = 'CreateFile' and ps.name = 'TeamViewer.exe' and file.operation = 'create' "
            "and file.extension in (%s)"
            % (', '.join([f'\'{ext}\'' for ext in extensions])))


@dotdictify
def on_next_kevent(kevent):
    emit_alert(
        f'Remote File Copy via TeamViewer',
        f'TeamViewer downloaded an executable or script file {kevent.kparams.file_name} via transfer session',
        severity=__severity__,
        tags=[__tags__]
    )

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
Watches files and directories created in the file system
"""

from filament.utils import dotdictify

__files__ = []


def on_init():
    kfilter("kevt.name = 'CreateFile' and file.operation = 'create'")
    columns(["Process", "File"])


@dotdictify
def on_next_kevent(kevent):
    file_name = kevent.kparams.file_name
    if file_name:
        __files__.append((kevent.exe, file_name, ))
        for f in __files__:
            add_row([f[0], f[1]])
        render_table()

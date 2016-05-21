# Copyright 2015/2016 by Nedim Sabic (RabbitStack)
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
Monitors the files created by processes
"""

files = []


def on_init():
    set_filter('CreateFile')
    columns(["Process", "File"])


def on_next_kevent(kevent):
    if kevent.params.operation == 'CREATE' \
            and kevent.params.file_type == 'FILE':
        files.append((kevent.thread.name, kevent.params.file, ))
        for f in files:
            add_row([f[0], f[1]])
        render_tabular()


def on_stop():
    pass


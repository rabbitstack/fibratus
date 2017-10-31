# Copyright 2016 by Nedim Sabic (RabbitStack)
# All Rights Reserved.
#
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
Performs the indexing of the kernel's event stream to
Elasticsearch on interval basis. When the scheduled
interval elapses, the list of documents aggregated
are indexed to Elasticsearch.
"""

from datetime import datetime
documents = []


def on_init():
    set_filter('CreateThread', 'CreateProcess', 'TerminateThread', 'TerminateProcess',
               'CreateFile', 'DeleteFile', 'WriteFile', 'RenameFile', 'Recv', 'Send',
               'Accept', 'Connect', 'Disconnect', 'LoadImage', 'UnloadImage',
               'RegCreateKey', 'RegDeleteKey', 'RegSetValue')
    set_interval(1)


def on_next_kevent(kevent):
    doco = {'image': kevent.thread.name,
            'thread': {
                'exe': kevent.thread.exe,
                'comm': kevent.thread.comm,
                'pid': kevent.thread.pid,
                'tid': kevent.tid,
                'ppid': kevent.thread.ppid},
            'category': kevent.category,
            'name': kevent.name,
            'ts': '%s %s' % (datetime.now().strftime('%m/%d/%Y'),
                             kevent.timestamp.strftime('%H:%M:%S')),
            'cpuid': kevent.cpuid,
            'params': kevent.params}
    documents.append(doco)


def on_interval():
    if len(documents) > 0:
        elasticsearch.emit(documents)
        documents.clear()

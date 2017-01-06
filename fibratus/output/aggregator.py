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
from fibratus.output.console import ConsoleOutput


class OutputAggregator(object):

    def __init__(self, outputs):
        self.outputs = outputs

    def aggregate(self, kevent):
        """Emit the kernel stream via output sinks.

        For each output registered, invokes the `emit``
        method to send the kernel event info to the
        output sink.

        Parameters
        ----------

        kevent: KEvent
            an instance of the kernel event
        """
        for _, output in self.outputs.items():
            if isinstance(output, ConsoleOutput):
                output.emit(kevent)
            else:
                pid, proc = kevent.get_thread()
                body = {'id': kevent.kid,
                        'timestamp': kevent.ts.strftime('%Y-%m-%d %H:%M:%S.%f'),
                        'cpuid': kevent.cpuid,
                        'proc': proc,
                        'pid': pid,
                        'name': kevent.name,
                        'category': kevent.category,
                        'params': kevent.params}
                output.emit(body)

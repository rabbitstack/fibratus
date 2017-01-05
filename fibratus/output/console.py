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
import json
from _ctypes import byref

from fibratus.apidefs.sys import get_std_handle, STD_OUTPUT_HANDLE, write_console_unicode, c_ulong
from fibratus.output.base import Output

RENDER_FORMAT = '%s %s %s %s (%s) - %s %s'


class ConsoleOutput(Output):

    def __init__(self, **kwargs):
        Output.__init__(self)

        self._fmt = kwargs.pop('format', 'pretty')
        self._timestamp_pattern = kwargs.pop('timestamp_pattern', '%Y-%m-%d %H:%M:%S.%f')
        self._stdout_handle = get_std_handle(STD_OUTPUT_HANDLE)

        assert self._stdout_handle, 'could not acquire the standard output stream handle'

    def emit(self, kevent, **kwargs):
        """Renders the kevent to the standard output stream.

        Uses the default output format or JSON to render the
        kernel event to standard output stream.

        The default output format is as follows:

        id  timestamp  cpu  process  (process id) - kevent (parameters)
        --  ---------  ---  -------  -----------   ------- ------------

        Example:

        160 13:27:27.554 0 wmiprvse.exe (1012) - CloseFile (file=C:\\WINDOWS\\SYSTEM32\\RSAENH.DLL, tid=2668)

        Parameters
        ----------

        kevent: KEvent
            the information regarding the kernel event

        kwargs: dict
            console adapter configuration

        """
        pid, proc = kevent.get_thread()
        if 'pretty' in self._fmt:
            kevt = RENDER_FORMAT % (kevent.kid,
                                    kevent.ts.time(),
                                    kevent.cpuid,
                                    proc,
                                    pid,
                                    kevent.name,
                                    self._format_params(kevent.params))
        else:
            kevt = json.dumps(dict(id=kevent.kid,
                                   timestamp=kevent.ts.strftime(self._timestamp_pattern),
                                   cpuid=kevent.cpuid,
                                   proc=proc,
                                   pid=pid,
                                   name=kevent.name,
                                   params=kevent.params))

        kevt += '\n'
        # write the output on the standard output stream
        write_console_unicode(self._stdout_handle, kevt,
                              len(kevt),
                              byref(c_ulong()),
                              None)

    def _format_params(self, kparams):
        """Transforms the kevent parameters.

        Apply the rendering format on the kevent payload
        to transform it into more convenient structure
        sorted by parameter keys.
        """
        fmt = ', '.join('%s=%s' % (k, kparams[k]) for k in sorted(kparams.keys())) \
            .replace('\"', '')
        return '(%s)' % fmt

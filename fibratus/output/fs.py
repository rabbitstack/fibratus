# Copyright 2017 by Nedim Sabic (RabbitStack)
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

from fibratus.output.base import Output
import io
import os
import time
import json


class FsOutput(Output):
    """File system output.

    Implementation of the output which writes the stream of
    kernel events to a file.
    """

    def __init__(self, **kwargs):
        Output.__init__(self)
        self._path = kwargs.pop('path', None)
        self._fmt = kwargs.pop('format', 'json')
        self._mode = kwargs.pop('mode', 'a')

        filename = os.path.join(self._path,
                                '%s.fibra' % time.strftime('%x')
                                .replace('/', '-'))
        self.stream = io.open(filename, self._mode)

    def emit(self, body, **kwargs):
        if 'json' in self._fmt:
            self.stream.write(json.dumps(body) + '\n')

    @property
    def path(self):
        return self._path

    @property
    def format(self):
        return self._fmt

    @property
    def mode(self):
        return self._mode
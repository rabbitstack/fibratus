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

from fibratus.binding.base import BaseBinding
from fibratus.errors import BindingError

import os
import glob

try:
    import yara
except ImportError:
    yara = None


class YaraBinding(BaseBinding):

    def __init__(self, outputs, logger, **config):
        """Creates an instance of the YARA binding.

        This binding integrates with YARA tool to provide real time classification and pattern matching of the
        process's binary images. The image path is extracted from the `ThreadInfo` instance after `CreateProcess`
        kernel event has been captured.

        :param dict outputs: declared output adapters
        :param logbook.Logger logger: reference to the logger implementation
        :param dict config: configuration for this binding
        """

        BaseBinding.__init__(self, outputs, logger)
        self._path = config.pop('path', None)
        self._rules = None
        if not yara:
            raise BindingError('yara-python package is not installed')
        if not os.path.exists(self._path) or not os.path.isdir(self._path):
            raise BindingError('%s rules path does not exist' %
                               self._path)
        try:
            for file in glob.glob(os.path.join(self._path, '*.yar')):
                self._rules = yara.compile(os.path.join(self._path, file))
        except yara.SyntaxError as e:
            raise BindingError("rule compilation error %s" % e)

    def run(self, **kwargs):
        """Apply the YARA rule set to process's image path.

        If a rule match occurs, the data with rule information, matching strings, process name, etc. is transported
        over provided output implementation. If output type is not specified, the console output stream is used.

        :param dict kwargs: parameters for the binding context
        """
        thread_info = kwargs.pop('thread_info', None)
        kevent = kwargs.pop('kevent', None)
        if thread_info:
            def yara_callback(data):
                matches = data['matches']
                if matches:
                    rule_context = {
                        'rule_info': {
                            'meta': data['meta'],
                            'tags': data['tags'],
                            'namespace': data['namespace'],
                            'rule': data['rule'],
                            'strings': [self.__string_meta(string) for string in data['strings']]
                        }
                    }
                    kevent.params.update(rule_context)
                return yara.CALLBACK_CONTINUE
            self._rules.match(thread_info.exe, callback=yara_callback)

    def __string_meta(self, string):
        """Unpacks the tuple with matching string data and transforms it to a dictionary.

        :param tuple string: the tuple with matching string data
        :return: dict:
        """
        offset, ident, data = string
        return {
            'offset': offset,
            'identifier': ident,
            'data': data.decode('utf-8')
        }

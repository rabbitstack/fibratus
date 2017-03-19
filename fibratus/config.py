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

import os
import anyconfig
from fibratus.common import panic, DotD as ddict

__DEFAULT_CONFIG_PATH__ = os.path.join(os.path.expanduser('~'), '.fibratus', 'fibratus.yml')


class YamlConfig(object):

    def __init__(self, config_path=None):
        path = os.getenv('FIBRATUS_CONFIG_PATH', __DEFAULT_CONFIG_PATH__)
        path = config_path or path
        try:
            self._yaml = anyconfig.load(path, ignore_missing=False)
        except FileNotFoundError:
            panic('ERROR - %s configuration file does not exist' % path)

    @property
    def image_meta(self):
        return ddict(self._yaml.pop('image_meta', {}))

    @property
    def skips(self):
        return ddict(self._yaml.pop('skips', {}))

    @property
    def outputs(self):
        return self._yaml.pop('output', None)

    @property
    def bindings(self):
        return self._yaml.pop('binding', None)

    @property
    def yaml(self):
        return self._yaml
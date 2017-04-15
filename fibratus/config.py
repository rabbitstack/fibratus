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
import sys
import anyconfig
from fibratus.common import panic, DotD as ddict
from pykwalify.core import Core


class YamlConfig(object):
    """YAML based configuration reader.

    Reads the configuration from YAML file, and ensures the content satisfies the structure
    as defined in the schema file.
    """

    def __init__(self, config_path=None):
        self._default_config_path = os.path.join(os.path.expanduser('~'), '.fibratus', 'fibratus.yml')
        self._default_schema_path = os.path.join(os.path.expanduser('~'), '.fibratus', 'schema.yml')
        self.path = config_path or os.getenv('FIBRATUS_CONFIG_PATH', self._default_config_path)
        self._yaml = None

    def load(self, validate=True):
        schema_file = os.path.join(sys._MEIPASS, 'schema.yml') \
            if hasattr(sys, '_MEIPASS') else self._default_schema_path
        try:
            self._yaml = anyconfig.load(self.path, ignore_missing=False)
        except FileNotFoundError:
            panic('ERROR - %s configuration file does not exist' % self.path)
        if validate:
            validator = Core(source_file=self.path, schema_files=[schema_file])
            validator.validate(raise_exception=True)

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

    @property
    def default_config_path(self):
        return self._default_config_path

    @default_config_path.setter
    def default_config_path(self, path):
        self._default_config_path = path

    @property
    def default_schema_path(self):
        return self._default_schema_path

    @default_schema_path.setter
    def default_schema_path(self, path):
        self._default_schema_path = path

    @property
    def config_path(self):
        return self.path
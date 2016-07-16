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
from unittest.mock import patch
from fibratus.config import YamlConfig

import os

__CONFIG_PATH__ = os.path.join(os.path.dirname(__file__), '..', 'fixtures', 'fibratus.yml')


class TestYamlConfig():

    def test_load_yaml(self):
        config = YamlConfig(__CONFIG_PATH__)
        assert config.yaml

    def test_load_yaml_not_found(self):
        with patch('sys.exit') as sys_exit:
            YamlConfig('C:\\fibratus.yml')
            sys_exit.assert_called_once()

    def test_output_adapters(self):
        config = YamlConfig(__CONFIG_PATH__)
        assert config.output_adapters
        assert isinstance(config.output_adapters, list)
        assert len(config.output_adapters) > 0

    def test_enum_output_adapters(self):
        config = YamlConfig(__CONFIG_PATH__)
        adapter_names = ['amqp', 'smtp']
        output_adapters = config.output_adapters
        if output_adapters:
            for output_adapter in output_adapters:
                adapter_name = next(iter(list(output_adapter.keys())), None)
                assert adapter_name in adapter_names
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

    def test_outputs(self):
        config = YamlConfig(__CONFIG_PATH__)
        outputs = config.outputs
        assert outputs
        assert isinstance(outputs, list)
        assert len(outputs) > 0

    def test_enum_outputs(self):
        config = YamlConfig(__CONFIG_PATH__)
        output_names = ['amqp', 'smtp', 'console', 'elasticsearch']
        outputs = config.outputs
        if outputs:
            for output in outputs:
                output_name = next(iter(list(output.keys())), None)
                assert output_name in output_names

    def test_image_skips(self):
        config = YamlConfig(__CONFIG_PATH__)
        image_skips = config.skips.images
        assert image_skips
        assert isinstance(image_skips, list)
        assert 'smss.exe' in image_skips
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
from unittest import mock
import os
import pytest

from fibratus.image_meta import ImageMetaRegistry


@pytest.fixture(scope='module')
def image_meta_registry():
    image_meta_registry = ImageMetaRegistry(imports=True, file_info=True)
    return image_meta_registry


@pytest.fixture(scope='module')
def image_path():
    return '%s\\notepad.exe' % os.environ['WINDIR']


class TestImageMetaRegistry(object):

    def test_add_image_meta(self, image_meta_registry, image_path):
        image_meta_registry.add_image_meta(image_path)
        image_meta = image_meta_registry.get_image_meta(image_path)
        assert image_meta

        assert image_meta.arch
        assert image_meta.timestamp
        assert image_meta.num_sections > 0

        assert len(image_meta.sections) > 0
        section_names = [se['name'] for se in image_meta.sections]

        assert '.text' in section_names

        assert len(image_meta.imports) > 0
        assert 'KERNEL32.dll' in image_meta.imports

        assert 'Microsoft Corporation' in image_meta.org
        assert image_meta.description
        assert image_meta.version
        assert 'Notepad' in image_meta.internal_name
        assert image_meta.copyright

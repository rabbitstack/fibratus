# Copyright 2016 by Nedim Sabic (RabbitStack)
# All Rights Reserved.
# http://rabbitstack.github.io

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
import pytest
from fibratus.asciiart.tabular import Tabular


@pytest.fixture()
def columns():
    return ['Description', 'Name', 'Category']


class TestTabular():

    def test_init_columns(self, columns):
        tabular = Tabular(columns)
        assert tabular.colcount == 3

    def test_init_align_col(self, columns):
        tabular = Tabular(columns, 'Description')
        assert tabular.align['Description'] == 'l'

    def test_init_sortby(self, columns):
        tabular = Tabular(columns, sort_by='Category')
        assert tabular.sortby == 'Category'
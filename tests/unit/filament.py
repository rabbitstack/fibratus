# Copyright 2015/2016 by Nedim Sabic (RabbitStack)
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
import os
from unittest.mock import Mock, patch
from apscheduler.schedulers.background import BackgroundScheduler
import pytest
from fibratus.errors import FilamentError
from fibratus.filament import Filament
import fibratus.filament as fil
from fibratus.term import AnsiTerm
from tests.fixtures.filaments import test_filament


@pytest.fixture(scope='module')
def ansi_term_mock():
    return Mock(spec_set=AnsiTerm)


@pytest.fixture(scope='module')
def filament(ansi_term_mock):
    fil.FILAMENTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'fixtures\\filaments')
    f = Filament()
    f.ansi_term = ansi_term_mock
    f.scheduler = Mock(spec_set=BackgroundScheduler)
    return f


class TestFilament():

    def test_load_filament(self, filament):
        with patch('os.listdir', return_value=['top_connections.py', 'test_filament.py']):
            filament.load_filament('test_filament')
            assert filament._filament
            assert isinstance(filament._filament, type(test_filament))
            assert filament._filament.__doc__

    def test_load_filament_not_found(self, filament):
        with patch('os.listdir', return_value=['top_connections.py', 'test_filament.py']):
            with pytest.raises(FilamentError):
                filament.load_filament('filament_notfound')

    def test_load_filament_nodoc(self, filament):
        with patch('os.listdir', return_value=['top_connections.py', 'test_filament_nodoc.py']):
            with pytest.raises(FilamentError) as e:
                filament.load_filament('test_filament_nodoc')
            assert "Please provide a short description for the filament" in str(e.value)

    def test_load_filament_no_on_next_kevent_method(self, filament):
        with patch('os.listdir', return_value=['top_connections.py', 'test_filament_no_on_next_kevent.py']):
            with pytest.raises(FilamentError) as e:
                filament.load_filament('test_filament_no_on_next_kevent')
            assert 'Missing required on_next_kevent method on filament' in str(e.value)

    def test_load_filament_wrong_on_next_kevent(self, filament):
        with patch('os.listdir', return_value=['test_filament_wrong_on_next_kevent.py']):
            with pytest.raises(FilamentError) as e:
                filament.load_filament('test_filament_wrong_on_next_kevent')
            assert 'one argument' in str(e.value)

    def test_initialize_filament(self, filament):
        with patch('os.listdir', return_value=['top_connections.py', 'test_filament.py']):
            filament.load_filament('test_filament')
            filament.initialize_filament()
            f = filament._filament
            assert hasattr(f, 'set_filter')
            assert hasattr(f, 'set_interval')
            assert hasattr(f, 'columns')
            assert hasattr(f, 'title')
            assert hasattr(f, 'sort_by')
            assert hasattr(f, 'limit')
            assert hasattr(f, 'add_row')
            assert hasattr(f, 'render_tabular')

            f.set_filter('CreateProcess', 'CreateThread')
            assert 'CreateProcess' in filament._filters
            assert 'CreateThread' in filament._filters

            f.set_interval(1)
            assert filament._interval == 1

            f.columns(['IP', 'Port', 'Process'])
            assert filament._cols == ['IP', 'Port', 'Process']

            f.limit(20)
            assert filament._limit == 20

    def test_set_invalid_interval(self, filament):
        with patch('os.listdir', return_value=['top_connections.py', 'test_filament_invalid_interval.py']):
            filament.load_filament('test_filament_invalid_interval')
            with pytest.raises(FilamentError) as e:
                filament.initialize_filament()



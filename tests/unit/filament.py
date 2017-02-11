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

import pytest
from apscheduler.schedulers.background import BackgroundScheduler

import fibratus.filament as fil
from fibratus.errors import FilamentError
from fibratus.filament import Filament
from fibratus.output.amqp import AmqpOutput
from fibratus.term import AnsiTerm
from tests.fixtures.filaments import test_filament


@pytest.fixture(scope='module')
def ansi_term_mock():
    return Mock(spec_set=AnsiTerm)


@pytest.fixture()
def filament(ansi_term_mock):
    fil.FILAMENTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'fixtures\\filaments')
    f = Filament()
    f._ansi_term = ansi_term_mock
    f.scheduler = Mock(spec_set=BackgroundScheduler)
    return f


class TestFilament(object):

    def test_load_filament(self, filament):
        with patch('os.listdir', return_value=['top_connections.py', 'test_filament.py']):
            filament.load_filament('test_filament')
            assert filament._filament_module
            assert isinstance(filament._filament_module, type(test_filament))
            assert filament._filament_module.__doc__
            assert 'test_filament' in filament.name

            f = filament.filament_module
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

            f.add_row(['192.168.1.3', '80', 'chrome.exe'])

            f.sort_by('Port')
            assert 'Port' in filament._sort_by
            assert filament._sort_desc

            f.title('Top outbound connections')

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

    def test_close(self, filament):
        filament.close()

    def test_set_invalid_interval(self, filament):
        with patch('os.listdir', return_value=['top_connections.py', 'test_filament_invalid_interval.py']):
            with pytest.raises(FilamentError):
                filament.load_filament('test_filament_invalid_interval')

    def test_add_row_invalid_type(self, filament):
        with patch('os.listdir', return_value=['test_filament.py']):
            filament.load_filament('test_filament')
            f = filament.filament_module
            with pytest.raises(FilamentError):
                f.add_row({'ip': '192.168.4.31'})

    def test_sort_by_no_columns(self, filament):
        with patch('os.listdir', return_value=['test_filament.py']):
            filament.load_filament('test_filament')
            f = filament.filament_module
            with pytest.raises(FilamentError) as e:
                f.sort_by('Port')
            assert 'Expected at least 1 column but 0 found' in str(e.value)

    def test_sort_by_column_not_found(self, filament):
        with patch('os.listdir', return_value=['test_filament.py']):
            filament.load_filament('test_filament')
            f = filament.filament_module
            f.columns(['IP', 'Port', 'Process'])
            with pytest.raises(FilamentError) as e:
                f.sort_by('File')
            assert 'File column does not exist' in str(e.value)

    def test_limit_no_columns(self, filament):
        with patch('os.listdir', return_value=['test_filament.py']):
            filament.load_filament('test_filament')
            f = filament.filament_module
            with pytest.raises(FilamentError):
                f.limit(20)

    def test_limit_non_integer(self, filament):
        with patch('os.listdir', return_value=['test_filament.py']):
            filament.load_filament('test_filament')
            f = filament.filament_module
            f.columns(['IP', 'Port', 'Process'])
            with pytest.raises(FilamentError):
                f.limit('20')

    def test_do_output_accessors(self, filament):
        with patch('os.listdir', return_value=['test_filament.py']):
            filament.load_filament('test_filament')
            outputs = {'amqp': Mock(spec_set=AmqpOutput)}
            filament.do_output_accessors(outputs)
            assert getattr(filament.filament_module, 'amqp')

    def test_set_columns_not_list(self, filament):
        with patch('os.listdir', return_value=['test_filament.py']):
            filament.load_filament('test_filament')
            with pytest.raises(FilamentError):
                filament.filament_module.columns(('IP', 'Port'))

    def test_render_tabular(self, filament, ansi_term_mock):
        with patch('os.listdir', return_value=['test_filament.py']):
            filament.load_filament('test_filament')
            filament.filament_module.columns(['IP', 'Port'])
            filament.render_tabular()
            ansi_term_mock.setup_console.assert_called_once()
            ansi_term_mock.write_output.assert_called_once()

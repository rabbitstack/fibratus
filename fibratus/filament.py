# Copyright 2015 by Nedim Sabic (RabbitStack)
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

from importlib.machinery import SourceFileLoader
import inspect
import os

import sys
from apscheduler.executors.pool import ThreadPoolExecutor
from apscheduler.schedulers.background import BackgroundScheduler
from prettytable import PrettyTable

from fibratus.common import IO
from fibratus.errors import FilamentError
from fibratus.term import AnsiTerm

FILAMENTS_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'filaments')


class Filament():
    """Filament initialization and execution engine.

    Filaments are lightweight Python modules which run
    on top of Fibratus. They are often used to enrich/extend the
    functionality of Fibratus by performing any type of logic
    (aggregations, groupings, filters, counters, etc) on the
    kernel event stream.

    """

    def __init__(self):
        self._filament = None
        self._filters = []
        self._tabular = None
        self._cols = []
        self._limit = 10
        self._interval = 1
        self._sort_by = None
        self._sort_desc = True
        self.ansi_term = AnsiTerm()
        self.scheduler = BackgroundScheduler()
        self.term_initialized = False
        self._on_stop = None

    def load_filament(self, name):
        Filament._assert_root_dir()
        [filament_path] = [os.path.join(FILAMENTS_DIR, filament) for filament in os.listdir(FILAMENTS_DIR)
                           if filament.endswith('.py') and name == filament[:-3]] or [None]
        if filament_path:
            loader = SourceFileLoader(name, filament_path)
            self._filament = loader.load_module()
            # check for required methods
            # on the filament module
            doc = inspect.getdoc(self._filament)
            if not doc:
                raise FilamentError("Please provide a short description for the filament")

            [on_next_kevent] = self._find_func('on_next_kevent')
            if on_next_kevent:
                args_spec = inspect.getargspec(on_next_kevent)
                if len(args_spec.args) != 1:
                    raise FilamentError('Missing one argument on_next_kevent method on filament')
            else:
                raise FilamentError('Missing required on_next_kevent method on filament')
        else:
            raise FilamentError('%s filament not found' % name)

    def initialize_filament(self):
        if self._filament:
            def set_filter(*args):
                self._filters = args
            self._filament.set_filter = set_filter

            def set_interval(interval):
                if not type(interval) is int:
                    raise FilamentError('Interval must be an integer value')
                self._interval = interval
            self._filament.set_interval = set_interval

            def columns(cols):
                if not isinstance(cols, list):
                    raise FilamentError('Columns must be a list, %s found' % type(cols))
                self._cols = cols
                self._tabular = PrettyTable(self._cols)
                self._tabular.padding_width = 10
                self._tabular.junction_char = '|'

            def sort_by(col, sort_desc=True):
                if len(self._cols) == 0:
                    raise FilamentError('Expected at least 1 column but 0 found')
                if not col in self._cols:
                    raise FilamentError('%s column does not exist' % col)
                self._sort_by = col
                self._sort_desc = sort_desc

            def limit(limit):
                if len(self._cols) == 0:
                    raise FilamentError('Expected at least 1 column but 0 found')
                if not type(limit) is int:
                    raise FilamentError('Limit must be an integer value')
                self._limit = limit

            def title(text):
                self._tabular.title = text

            def add_row(row):
                if not isinstance(row, list):
                    raise FilamentError('Expected list type for the row')
                self._tabular.add_row(row)

            self._filament.columns = columns
            self._filament.title = title
            self._filament.sort_by = sort_by
            self._filament.limit = limit
            self._filament.add_row = add_row
            self._filament.render_tabular = self.render_tabular

            # call filaments methods if defined
            [on_init] = self._find_func('on_init')
            if on_init:
                if len(inspect.getargspec(on_init).args) == 0:
                    self._filament.on_init()

            [on_stop] = self._find_func('on_stop')
            if on_stop:
                if len(inspect.getargspec(on_stop).args) == 0:
                    self._on_stop = on_stop

            [on_interval] = self._find_func('on_interval')
            if on_interval:
                self.scheduler.add_executor(ThreadPoolExecutor(max_workers=8))
                self.scheduler.start()
                self.scheduler.add_job(self._filament.on_interval,
                                       'interval',
                                       seconds=1, max_instances=8,
                                       misfire_grace_time=60)

    def render_tabular(self):
        if len(self._cols) > 0:
            tabular = self._tabular.get_string(start=1, end=self._limit)
            if self._sort_by:
                tabular = self._tabular.get_string(start=1, end=self._limit,
                                                   sortby=self._sort_by,
                                                   reversesort=self._sort_desc)
            if not self.term_initialized:
                self.term_initialized = True
                self.ansi_term.init_console()
            self._tabular.clear_rows()
            self.ansi_term.cls()
            self.ansi_term.write(tabular)

    def process(self, kevent):
        self._filament.on_next_kevent(kevent)

    def close(self):
        if self._on_stop:
            self._on_stop()
        if self.scheduler.running:
            self.scheduler.shutdown()
        self.ansi_term.restore_console()

    @classmethod
    def exists(cls, filament):
        Filament._assert_root_dir()
        return os.path.exists(os.path.join(FILAMENTS_DIR, '%s.py' % filament))

    @classmethod
    def list_filaments(cls):
        Filament._assert_root_dir()
        filaments = {}
        paths = [os.path.join(FILAMENTS_DIR, path) for path in os.listdir(FILAMENTS_DIR)
                 if path.endswith('.py')]
        for path in paths:
            filament_name = os.path.basename(path)[:-3]
            loader = SourceFileLoader(filament_name, path)
            filament = loader.load_module()
            filaments[filament_name] = inspect.getdoc(filament)
        return filaments

    @property
    def filters(self):
        return self._filters

    @classmethod
    def _assert_root_dir(cls):
        if not os.path.exists(FILAMENTS_DIR):
            IO.write_console('fibratus run: ERROR - %s path does not exist.' % FILAMENTS_DIR)
            sys.exit(0)

    def _find_func(self, func_name):
        functions = inspect.getmembers(self._filament, predicate=inspect.isfunction)
        return [func for name, func in functions if name == func_name] or [None]

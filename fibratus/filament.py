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

import inspect
import traceback
import os
import sys
from importlib.machinery import SourceFileLoader

from apscheduler.executors.pool import ThreadPoolExecutor
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from fibratus.common import DotD as ddict, Tabular
from fibratus.common import panic
from fibratus.errors import FilamentError, TermInitializationError
from fibratus.term import AnsiTerm


FILAMENTS_DIR = os.getenv('FILAMENTS_PATH', os.path.join(os.path.expanduser('~'), '.fibratus', 'filaments'))


class OutputAccessor(object):
    """An accessor for the output meta variable.

    It represents an output accessor which is injected into
    every filament module.
    """
    def __init__(self, output):
        self._output = output

    def emit(self, body, **kwargs):
        self._output.emit(body, **kwargs)


class Filament(object):
    """Filament initialization and execution engine.

    Filaments are lightweight Python modules which run
    on top of Fibratus. They are often used to enrich/extend the
    functionality of Fibratus by performing any type of logic
    (aggregations, groupings, filters, counters, etc) on the
    kernel event stream.

    """
    def __init__(self):
        """Builds a new instance of the filament.

        Attributes:
        ----------

        filament_module: module
            module which contains the filament logic
        """
        self._filament_module = None
        self._name = None
        self._filters = []
        self._cols = []
        self._tabular = None
        self._limit = 10
        self._interval = 1
        self._sort_by = None
        self._sort_desc = True
        self._logger = None
        self._ansi_term = AnsiTerm()
        self.scheduler = BackgroundScheduler()

    def load_filament(self, name):
        """Loads the filament module.

        Finds and loads the python module which
        holds the filament logic. It also looks up for
        some essential filament methods and raises an error
        if they can't be found.

        Parameters
        ----------
        name: str
            name of the filament to load

        """
        self._name = name
        Filament._assert_root_dir()
        filament_path = self._find_filament_path(name)
        if filament_path:
            loader = SourceFileLoader(name, filament_path)
            self._filament_module = loader.load_module()
            sys.path.append(FILAMENTS_DIR)
            doc = inspect.getdoc(self._filament_module)
            if not doc:
                raise FilamentError('Please provide a short '
                                    'description for the filament')

            on_next_kevent = self._find_filament_func('on_next_kevent')
            if on_next_kevent:
                if self._num_args(on_next_kevent) != 1:
                    raise FilamentError('Missing one argument on_next_kevent '
                                        'method on filament')
                self._initialize_funcs()
            else:
                raise FilamentError('Missing required on_next_kevent '
                                    'method on filament')
        else:
            raise FilamentError('%s filament not found' % name)

    def _initialize_funcs(self):
        """Setup the filament modules functions.

        Functions
        ---------

        set_filter: func
            accepts the comma separated list of kernel events
            for whose the filter should be applied
        set_interval: func
            establishes the fixed repeating interval in seconds
        columns: func
            configure the column set for the table
        add_row: func
            adds a new row to the table
        sort_by: func
            sorts the table by specific column
        """

        def set_filter(*args):
            self._filters = args
        self._filament_module.set_filter = set_filter

        def set_interval(interval):
            if not type(interval) is int:
                raise FilamentError('Interval must be an integer value')
            self._interval = interval
        self._filament_module.set_interval = set_interval

        def columns(cols):
            if not isinstance(cols, list):
                raise FilamentError('Columns must be a list, '
                                    '%s found' % type(cols))
            self._cols = cols
            self._tabular = Tabular(self._cols)
            self._tabular.padding_width = 10
            self._tabular.junction_char = '|'

        def add_row(row):
            if not isinstance(row, list):
                raise FilamentError('Expected list type for the row, found %s'
                                    % type(row))
            self._tabular.add_row(row)

        def sort_by(col, sort_desc=True):
            if len(self._cols) == 0:
                raise FilamentError('Expected at least 1 column but 0 found')
            if col not in self._cols:
                raise FilamentError('%s column does not exist' % col)
            self._sort_by = col
            self._sort_desc = sort_desc

        def limit(l):
            if len(self._cols) == 0:
                raise FilamentError('Expected at least 1 column but 0 found')
            if not type(l) is int:
                raise FilamentError('Limit must be an integer value')
            self._limit = l

        def title(text):
            self._tabular.title = text

        self._filament_module.columns = columns
        self._filament_module.title = title
        self._filament_module.sort_by = sort_by
        self._filament_module.limit = limit
        self._filament_module.add_row = add_row
        self._filament_module.render_tabular = self.render_tabular

        on_init = self._find_filament_func('on_init')
        if on_init and self._zero_args(on_init):
            self._filament_module.on_init()
        if self._find_filament_func('on_interval'):
            self.scheduler.add_executor(ThreadPoolExecutor(max_workers=4))
            self.scheduler.start()

            def on_interval():
                try:
                    self._filament_module.on_interval()
                except Exception:
                    self._logger.error('Unexpected error on interval elapsed %s'
                                       % traceback.format_exc())
            self.scheduler.add_job(on_interval,
                                   IntervalTrigger(),
                                   seconds=self._interval,
                                   max_instances=4,
                                   misfire_grace_time=60)
        if len(self._cols) > 0:
            try:
                self._ansi_term.setup_console()
            except TermInitializationError:
                panic('fibratus run: ERROR - console initialization failed')

    def do_output_accessors(self, outputs):
        """Creates the filament's output accessors.

        Parameters
        ----------

        outputs: dict
            outputs initialized from the configuration
            descriptor
        """
        for name, output in outputs.items():
            setattr(self._filament_module, name, OutputAccessor(output))

    def on_next_kevent(self, kevent):
        try:
            self._filament_module.on_next_kevent(ddict(kevent))
        except Exception as e:
            self._logger.error('Unexpected filament error %s' % e)

    def render_tabular(self):
        """Renders the table on the console.
        """
        if len(self._cols) > 0:
            tabular = self._tabular.get_string(start=1, end=self._limit)
            if self._sort_by:
                tabular = self._tabular.get_string(start=1, end=self._limit,
                                                   sortby=self._sort_by,
                                                   reversesort=self._sort_desc)
            self._tabular.clear_rows()
            self._ansi_term.write_output(tabular)

    def close(self):
        on_stop = self._find_filament_func('on_stop')
        if on_stop and self._zero_args(on_stop):
            self._filament_module.on_stop()
        if self.scheduler.running:
            self.scheduler.shutdown()
        self._ansi_term.restore_console()

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

    @classmethod
    def _assert_root_dir(cls):
        if not os.path.exists(FILAMENTS_DIR):
            panic('fibratus run: ERROR - %s path does not exist.' % FILAMENTS_DIR)

    @property
    def filters(self):
        return self._filters

    @property
    def logger(self):
        return self._logger

    @logger.setter
    def logger(self, logger):
        self._logger = logger

    @property
    def filament_module(self):
        return self._filament_module

    @property
    def name(self):
        return self._name

    def _find_filament_func(self, func_name):
        """Finds the function in the filament module.

        Parameters
        ----------

        func_name: str
            the name of the function
        """
        functions = inspect.getmembers(self._filament_module, predicate=inspect.isfunction)
        return next(iter([func for name, func in functions if name == func_name]), None)

    def _find_filament_path(self, filament_name):
        """Resolves the filament full path from the name

        Parameters
        ----------

        filament_name: str
            the name of the filament whose path if about to be resolved
        """
        return next(iter([os.path.join(FILAMENTS_DIR, filament) for filament in os.listdir(FILAMENTS_DIR)
                    if filament.endswith('.py') and filament_name == filament[:-3]]), None)

    def _num_args(self, func):
        return len(inspect.getargspec(func).args)

    def _zero_args(self, func):
        return self._num_args(func) == 0

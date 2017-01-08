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
from unittest.mock import Mock

import pytest

from fibratus.kevent import KEvent
from fibratus.output.aggregator import OutputAggregator
from fibratus.output.amqp import AmqpOutput
from fibratus.output.console import ConsoleOutput


@pytest.fixture(scope='module')
def outputs():
    return dict(amqp=Mock(spec_set=AmqpOutput), console=Mock(spec_set=ConsoleOutput))


@pytest.fixture(scope='module')
def output_aggregator(outputs):
    return OutputAggregator(outputs)


@pytest.fixture(scope='module')
def kevent():
    kevent_mock = Mock(spec_set=KEvent)
    kevent_mock.get_thread.return_value = (343, 'svchost.exe')
    return kevent_mock


class TestOutputAggregator(object):

    def test_aggregate(self, output_aggregator, kevent, outputs):
        output_aggregator.aggregate(kevent)
        for _, output in outputs.items():
            assert output.emit.call_count == 1


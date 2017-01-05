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
import json
from unittest.mock import patch

import pika
import pytest

from fibratus.errors import InvalidPayloadError
from fibratus.output.amqp import AmqpOutput


@pytest.fixture(scope='module')
def amqp_adapter():
    config = {
        'username': 'fibratus',
        'host': '127.0.0.1',
        'port': 5672,
        'vhost': '/',
        'exchange': 'test',
        'routingkey': 'fibratus'
    }
    return AmqpOutput(**config)


class TestAmqpOutput(object):

    def test_init(self, amqp_adapter):
        assert 'fibratus' in amqp_adapter.username
        assert 'guest' in amqp_adapter._password
        assert '127.0.0.1' in amqp_adapter.host
        assert amqp_adapter.port == 5672
        assert '/' in amqp_adapter.vhost
        assert 'test' in amqp_adapter.exchange
        assert 'fibratus' in amqp_adapter.routingkey
        assert amqp_adapter.delivery_mode == 1

    @patch('pika.BlockingConnection', spec_set=pika.BlockingConnection)
    def test_emit(self, connection_mock, amqp_adapter):
        body = {'kevent_type': 'CreateProcess'}
        amqp_adapter.emit(body)
        connection_mock.channel.assert_called_once()
        amqp_adapter._channel.basic_publish.assert_called_with('test', 'fibratus',
                                                               json.dumps(body),
                                                               amqp_adapter._basic_props)

    @patch('pika.BlockingConnection', spec_set=pika.BlockingConnection)
    def test_emit_invalid_payload(self, connection_mock, amqp_adapter):
        body = ['CrateProcess', 'TerminateProcess']
        with pytest.raises(InvalidPayloadError) as e:
            connection_mock.channel.assert_called_once()
            amqp_adapter.emit(body)
        assert "invalid payload for AMQP message. dict expected but <class 'list'> found" == str(e.value)
        amqp_adapter._channel.basic_publish.assert_not_called()

    @patch('pika.BlockingConnection', spec_set=pika.BlockingConnection)
    def test_emit_override_exchange_and_rk(self, connection_mock, amqp_adapter):
        body = {'kevent_type': 'CreateProcess'}
        amqp_adapter.emit(body, exchange='test.override', routingkey='fibratus.override')
        amqp_adapter._channel.basic_publish.assert_called_with('test.override', 'fibratus.override',
                                                               json.dumps(body),
                                                               amqp_adapter._basic_props)

    @pytest.mark.parametrize('body', [{'kevent_type': 'CreateProcess'}, {'kevent_type': 'TerminateProcess'},
                                      {'kevent_type': 'WriteFile'}, {'kevent_type': 'Recv'}])
    @patch('pika.BlockingConnection', spec_set=pika.BlockingConnection)
    def test_emit_multiple(self, connection_mock, body, amqp_adapter):
        amqp_adapter.emit(body, exchange='test.override', routingkey='fibratus.override')
        connection_mock.channel.assert_called_once()
        amqp_adapter._channel.basic_publish.assert_called_with('test.override', 'fibratus.override',
                                                               json.dumps(body),
                                                               amqp_adapter._basic_props)

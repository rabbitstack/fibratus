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
import pika

from fibratus.errors import InvalidAmqpPayloadError
from fibratus.output.adapter.base import BaseAdapter


class AmqpAdapter(BaseAdapter):

    def __init__(self, **kwargs):
        """Builds a new instance of the AMQP output adapter.

        Parameters
        ----------

        kwargs: dict
            AMQP configuration
        """
        BaseAdapter.__init__(self)
        self._username = kwargs.pop('username', 'guest')
        self._password = kwargs.pop('password', 'guest')

        self._host = kwargs.pop('host', '127.0.0.1')
        self._port = kwargs.pop('port', 5672)
        self._vhost = kwargs.pop('vhost', '/')
        self._delivery_mode = kwargs.pop('delivery_mode', 1)

        credentials = pika.PlainCredentials(self._username, self._password)
        self._parameters = pika.ConnectionParameters(self._host,
                                                     self._port,
                                                     self._vhost,
                                                     credentials)

        self._exchange = kwargs.pop('exchange', None)
        self._routingkey = kwargs.pop('routingkey', None)

        self._connection = None
        self._channel = None

        self._basic_props = pika.BasicProperties(content_type='text/json',
                                                 delivery_mode=self._delivery_mode)

    def emit(self, body, **kwargs):
        if not self._connection:
            self._connection = pika.BlockingConnection(self._parameters)
            self._channel = self._connection.channel()
        # override the default exchange name
        # and the routing key used to send
        # the message to the AMQP broker
        self._routingkey = kwargs.pop('routingkey', self._routingkey)
        self._exchange = kwargs.pop('exchange', self._exchange)

        # the message body should be a dictionary
        if not isinstance(body, dict):
            raise InvalidAmqpPayloadError('invalid payload for AMQP message. '
                                          'dict expected but %s found'
                                          % type(body))
        body = json.dumps(body)
        self._channel.basic_publish(self._exchange,
                                    self._routingkey,
                                    body, self._basic_props)

    @property
    def username(self):
        return self._username

    @property
    def host(self):
        return self._host

    @property
    def port(self):
        return self._port

    @property
    def vhost(self):
        return self._vhost

    @property
    def exchange(self):
        return self._exchange

    @property
    def routingkey(self):
        return self._routingkey

    @property
    def delivery_mode(self):
        return self._delivery_mode

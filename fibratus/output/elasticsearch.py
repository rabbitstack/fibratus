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

import elasticsearch
import elasticsearch.helpers

from fibratus.errors import InvalidPayloadError
from fibratus.output.base import Output


class ElasticsearchOutput(Output):

    def __init__(self, **kwargs):
        """Creates an instance of the Elasticsearch output adapter.

        Parameters
        ----------

        kwargs: dict
            Elasticsearch cluster configuration
        """
        Output.__init__(self)

        hosts = kwargs.pop('hosts', [])
        self._hosts = [dict(host=host.split(':')[0], port=int(host.split(':')[1])) for host in hosts]
        self._index_name = kwargs.pop('index', None)
        self._document_type = kwargs.pop('document', None)
        self._bulk = kwargs.pop('bulk', False)
        self._username = kwargs.pop('username', None)
        self._password = kwargs.pop('password', None)
        self._config = {}
        if self._username and self._password:
            self._config['http_auth'] = (self._username, self._password,)
        self._config['use_ssl'] = kwargs.pop('ssl', False)
        self._elasticsearch = None

    def emit(self, body, **kwargs):
        if not self._elasticsearch:
            self._elasticsearch = elasticsearch.Elasticsearch(self._hosts, **self._config)
        if self._bulk:
            if not isinstance(body, list):
                raise InvalidPayloadError('invalid payload for bulk indexing. '
                                          'list expected but %s found'
                                          % type(body))
        else:
            if not isinstance(body, dict):
                raise InvalidPayloadError('invalid payload for document. '
                                          'dict expected but %s found'
                                          % type(body))

        self._index_name = kwargs.pop('index', self._index_name)
        if self._bulk:
            actions = [dict(_index=self._index_name, _type=self._document_type, _source=b) for b in body]
            elasticsearch.helpers.bulk(self._elasticsearch, actions)
        else:
            self._elasticsearch.index(self._index_name, self._document_type, body=body)

    @property
    def hosts(self):
        return self._hosts

    @property
    def index_name(self):
        return self._index_name

    @property
    def document_type(self):
        return self._document_type

    @property
    def bulk(self):
        return self._bulk

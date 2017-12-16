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
from unittest.mock import patch
from datetime import datetime

import time
import elasticsearch
import pytest
from unittest.mock import Mock

from fibratus.errors import InvalidPayloadError
from fibratus.output.elasticsearch import ElasticsearchOutput


@pytest.fixture(scope='module')
def elasticsearch_adapter():
    config = {
        'hosts': [
            'localhost:9200',
            'rabbitstack:9200'
        ],
        'index': 'kernelstream',
        'document': 'threads',
    }
    return ElasticsearchOutput(**config)


@pytest.fixture(scope='module')
def elasticsearch_bulk_adapter():
    config = {
        'hosts': [
            'localhost:9200',
            'rabbitstack:9200'
        ],
        'index': 'kernelstream',
        'document': 'threads',
        'bulk': True,
        'username': 'elastic',
        'password': 'changeme'
    }
    return ElasticsearchOutput(**config)


@pytest.fixture(scope='module')
def elasticsearch_adapter_daily_index():
    config = {
        'hosts': [
            'localhost:9200',
            'rabbitstack:9200'
        ],
        'index': 'kernelstream',
        'document': 'threads',
        'index_type': 'daily'
    }
    return ElasticsearchOutput(**config)


mock_time = Mock()
mock_time.return_value = time.mktime(datetime(2017, 12, 16).timetuple())


class TestElasticsearchOutput(object):

    def test_init(self, elasticsearch_adapter):
        assert isinstance(elasticsearch_adapter.hosts, list)
        assert len(elasticsearch_adapter.hosts) > 0
        assert {'host': 'localhost', 'port': 9200} in elasticsearch_adapter.hosts
        assert elasticsearch_adapter.index_name == 'kernelstream'
        assert elasticsearch_adapter.document_type == 'threads'
        assert not elasticsearch_adapter.bulk

    def test_emit(self, elasticsearch_adapter):
        body = {'kevent_type': 'CreateProcess', 'params': {'name': 'smss.exe'}}
        assert elasticsearch_adapter._elasticsearch is None
        with patch('elasticsearch.Elasticsearch', spec_set=elasticsearch.Elasticsearch) as es_client_mock:
            elasticsearch_adapter.emit(body)
            es_client_mock.assert_called_with([{'host': 'localhost', 'port': 9200},
                                               {'host': 'rabbitstack', 'port': 9200}], use_ssl=False)
            elasticsearch_adapter._elasticsearch.index.assert_called_with('kernelstream', 'threads', body=body)

    @patch('time.time', mock_time)
    def test_emit_daily_index(self, elasticsearch_adapter_daily_index):
        body = {'kevent_type': 'CreateProcess', 'params': {'name': 'smss.exe'}}
        assert elasticsearch_adapter_daily_index._elasticsearch is None
        assert elasticsearch_adapter_daily_index.index_type == 'daily'
        with patch('elasticsearch.Elasticsearch', spec_set=elasticsearch.Elasticsearch) as es_client_mock:
            elasticsearch_adapter_daily_index.emit(body)
            es_client_mock.assert_called_with([{'host': 'localhost', 'port': 9200},
                                               {'host': 'rabbitstack', 'port': 9200}], use_ssl=False)
            elasticsearch_adapter_daily_index._elasticsearch.index.assert_called_with('kernelstream-2017.12.16', 'threads', body=body)

    @patch('elasticsearch.Elasticsearch', spec_set=elasticsearch.Elasticsearch)
    def test_emit_invalid_payload(self, es_client_mock, elasticsearch_adapter):
        body = ['CreateProcess', 'TerminateProcess']
        with pytest.raises(InvalidPayloadError) as e:
            elasticsearch_adapter.emit(body)
        assert "invalid payload for document. dict expected but <class 'list'> found" == str(e.value)
        assert es_client_mock.index.assert_not_called()

    @patch('elasticsearch.Elasticsearch', spec_set=elasticsearch.Elasticsearch)
    @patch('elasticsearch.helpers.bulk')
    def test_emit_bulk(self, es_bulk_mock, es_client_mock, elasticsearch_bulk_adapter):
        body = [{'kevent_type': 'CreateProcess', 'params': {'name': 'smss.exe'}},
                {'kevent_type': 'TerminateProcess', 'params': {'name': 'smss.exe'}}]
        elasticsearch_bulk_adapter.emit(body)
        es_client_mock.assert_called_with([{'host': 'localhost', 'port': 9200},
                                           {'host': 'rabbitstack', 'port': 9200}], use_ssl=False,
                                          http_auth=('elastic', 'changeme',))
        expected_body = [{'_index': 'kernelstream', '_type': 'threads', '_source':
                                    {'kevent_type': 'CreateProcess', 'params': {'name': 'smss.exe'}}},
                         {'_index': 'kernelstream', '_type': 'threads', '_source':
                                    {'kevent_type': 'TerminateProcess', 'params': {'name': 'smss.exe'}}}]
        es_bulk_mock.assert_called_once_with(elasticsearch_bulk_adapter._elasticsearch, expected_body)

    @patch('elasticsearch.Elasticsearch', spec_set=elasticsearch.Elasticsearch)
    @patch('elasticsearch.helpers.bulk')
    def test_emit_bulk_invalid_payload(self, es_bulk_mock, es_client_mock, elasticsearch_bulk_adapter):
        body = ({'kevent_type': 'CreateProcess', 'params': {'name': 'smss.exe'}},
                {'kevent_type': 'TerminateProcess', 'params': {'name': 'smss.exe'}},)
        with pytest.raises(InvalidPayloadError) as e:
            elasticsearch_bulk_adapter.emit(body)
        assert "invalid payload for bulk indexing. list expected but <class 'tuple'> found" == str(e.value)
        assert es_bulk_mock.assert_not_called()



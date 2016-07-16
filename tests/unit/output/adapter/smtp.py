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
import smtplib
from unittest.mock import patch, Mock

import pytest
from logbook import Logger

from fibratus.output.adapter.smtp import SmtpAdapter


@pytest.fixture(scope='module')
def smtp_adapter():
    config = {
        'host': 'smtp.gmail.com',
        'from': 'fibratus@fibratus.io',
        'password': 'secret',
        'to': ['fibratus@fibratus.io', 'netmutatus@netmutatus.io']
    }
    return SmtpAdapter(**config)


class TestSmtpAdapter(object):

    def test_init(self, smtp_adapter):
        assert 'smtp.gmail.com' in smtp_adapter.host
        assert 'fibratus@fibratus.io' in smtp_adapter.sender
        assert set(['fibratus@fibratus.io', 'netmutatus@netmutatus.io']) == set(smtp_adapter.to)
        assert smtp_adapter.port == 587

    def test_emit(self, smtp_adapter):
        body = 'Anomalous network activity detected from notepad.exe process'
        with patch('smtplib.SMTP'):
            smtp_adapter.emit(body, subject='Anomalous network activity detected')
            assert smtp_adapter._smtp.ehlo.call_count == 2
            smtp_adapter._smtp.starttls.assert_called_once()
            smtp_adapter._smtp.login.assert_called_with('fibratus@fibratus.io', 'secret')
            message = 'From: fibratus@fibratus.io' \
                      'To: fibratus@fibratus.io, netmutatus@netmutatus.io' \
                      'Subject: Anomalous network activity detected' \
                      'Anomalous network activity detected from notepad.exe process'

            smtp_adapter._smtp.login.sendmail('fibratus@fibratus.io', ['fibratus@fibratus.io',
                                                                       'netmutatus@netmutatus.io'],
                                              message)
            smtp_adapter._smtp.quit.assert_called_once()

    def test_emit_invalid_credentials(self, smtp_adapter):
        body = 'Anomalous network activity detected from notpead.exe process'
        smtp_adapter.logger = Mock(spec_set=Logger)
        with patch('smtplib.SMTP'):
            smtp_adapter._smtp.login.side_effect = smtplib.SMTPAuthenticationError(534, 'Invalid smtp credentials')
            smtp_adapter.emit(body, subject='Anomalous network activity detected')
            smtp_adapter.logger.error.assert_called_with('Invalid SMTP credentials for '
                                                         'fibratus@fibratus.io account')
            smtp_adapter._smtp.quit.assert_called_once()

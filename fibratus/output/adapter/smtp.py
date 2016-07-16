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

import os
import smtplib

from fibratus.output.adapter.base import BaseAdapter


class SmtpAdapter(BaseAdapter):

    def __init__(self, **kwargs):
        """Constructs a new instance of the SMTP outbound adapter.

        Parameters
        ----------

        kwargs: dict
            SMTP server and account configuration
        """
        BaseAdapter.__init__(self)
        self._host = kwargs.pop('host', None)
        self._port = kwargs.pop('port', 587)
        self._from = kwargs.pop('from', None)
        self._to = kwargs.pop('to', [])
        self._password = kwargs.pop('password', None) or \
            os.environ.get('SMTP_PASS')
        self._smtp = None

    def emit(self, body, **kwargs):
        if not self._smtp:
            self._smtp = smtplib.SMTP(self._host, self._port)
        self._smtp.ehlo()
        self._smtp.starttls()
        self._smtp.ehlo()
        subject = kwargs.pop('subject', '')
        message = self._compose_message(subject, body)
        # try to authenticate with the server
        # before attempting to send the message
        try:
            self._smtp.login(self._from, self._password)
            self._smtp.sendmail(self._from, self._to, message)
        except smtplib.SMTPAuthenticationError:
            self.logger.error('Invalid SMTP credentials for %s account'
                              % self._from)
        finally:
            self._smtp.quit()

    def _compose_message(self, subject, body):
        return """From: %s\r\nTo: %s\r\nSubject: %s\r\n\

                    %s
                """ % (self._from, ", ".join(self._to),
                       subject, body)

    @property
    def host(self):
        return self._host

    @property
    def port(self):
        return self._port

    @property
    def sender(self):
        return self._from

    @property
    def to(self):
        return self._to

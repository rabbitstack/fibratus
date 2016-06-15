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

import smtplib
import os


class AlarmTransport(object):

    def emit(self, title, body, **kwargs):
        raise NotImplementedError()


class SmtpAlarm(AlarmTransport):

    def __init__(self, host, password=None, port=25):
        self._smtp = smtplib.SMTP(host, port)
        self._password = os.environ.get('SMTP_ALARM_PASS') or password

    def emit(self, title, body, **kwargs):
        to_addrs = kwargs['to_addrs'] or None
        from_addr = kwargs['from_addr'] or None
        # compose the mail message
        if to_addrs and from_addr:
            msg = """From: %s\r\nTo: %s\r\nSubject: %s\r\n\

            %s
            """ % (from_addr, ", ".join(to_addrs), title, body)
            self._smtp.ehlo()
            # switch connection to TLS mode
            self._smtp.starttls()
            self._smtp.ehlo()
            # authenticate with the SMTP server
            self._smtp.login(from_addr, self._password)
            # send the email and close the session
            self._smtp.sendmail(from_addr, to_addrs, msg)
            self._smtp.quit()

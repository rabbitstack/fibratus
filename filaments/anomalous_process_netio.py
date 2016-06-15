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

"""
An unusual process attempts to make a network request or it accepts
the incoming connection.
"""

from filaments.support.alarm import SmtpAlarm

processes = ['notepad.exe', 'calc.exe', 'mspaint.exe']
activations = []

smtp_alarm = SmtpAlarm('smtp.live.com', port=587)
from_addr = 'from@domain.com'
to_addrs = ['to@domain.com']


def on_init():
    set_filter('Send', 'Accept', 'Recv', 'Connect')


def on_next_kevent(kevent):
    if kevent.thread:
        process_name = kevent.thread.name
        if process_name in processes:
            triggered = True if process_name in activations else False
            if not triggered:
                # compose the message
                message = 'Unusual network activity of kind %s ' \
                          'detected from %s process. ' \
                          'The source ip address is %s and ' \
                          'the destination ip address is %s' \
                           % (kevent.name, process_name,
                              kevent.params.ip_src,
                              kevent.params.ip_dst)
                # send the alarm via smtp transport
                smtp_alarm.emit('Anomalous network activity detected',
                                message, from_addr=from_addr, to_addrs=to_addrs)
                activations.append(process_name)

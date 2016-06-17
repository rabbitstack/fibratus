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
Triggers when a process creates the registry value which
would enable it to execute on system startup.
"""

from filaments.support.alarm import SmtpAlarm
smtp_alarm = SmtpAlarm('smtp.live.com', port=587)

keys = ['Run', 'RunOnce', 'RunServices', 'RunServicesOnce', 'Userinit']

from_addr = 'from@domain.com'
to_addrs = ['to@domain.com']


def on_init():
    set_filter('RegSetValue')


def on_next_kevent(kevent):
    if kevent.thread:
        process_name = kevent.thread.name
        key = kevent.params.key
        if key in keys:
            # compose the message
            message = 'The process %s has created a ' \
                      'persistent registry value , ' \
                      'under %s with content %s' \
                       % (process_name,
                          '%s/%s' % (kevent.params.hive, key),
                          kevent.params.value)
            # send the alarm via smtp transport
            smtp_alarm.emit('Registry persistence detected',
                            message, from_addr=from_addr, to_addrs=to_addrs)
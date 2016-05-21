# Copyright 2015 by Nedim Sabic (RabbitStack)
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


class KTraceError(Exception):
    pass


class FibratusError(Exception):
    pass


class FilamentError(Exception):
    pass


class TermInitializationError(Exception):
    pass


class UnknownKeventTypeError(Exception):

    def __init__(self, kevent):
        Exception.__init__(self, '%s cannot be recognized as a valid kernel event'
                           % kevent)


class HandleEnumError(Exception):

    def __init__(self, status):
        Exception.__init__(self, 'Unable to enumerate handles. Error code %s'
                           % status)




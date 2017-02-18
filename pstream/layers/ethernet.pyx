# Copyright 2017 by Nedim Sabic (RabbitStack)
# http://rabbitstack.github.io
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

import struct

cdef class Ethernet(BaseLayer):

    def __cinit__(self):
        self.dst_mac = 'ff:ff:ff:ff:ff:ff'
        self.src_mac = 'ff:ff:ff:ff:ff:ff'
        self.ethernet_type = 80

    cdef layer_type(self):
        pass

    cdef decode(self, byte [:] packet):
        if packet.nbytes < 14:
            return
        self.dst_mac = "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB", packet[0:6])
        self.src_mac = "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB", packet[6:12])
        self.ethernet_type = hex(struct.unpack('!H', packet[12:14])[0])

    cdef serialize(self):
        return {
            'dst_mac': self.dst_mac,
            'src_mac': self.src_mac,
            'ethernet_type': self.ethernet_type
        }
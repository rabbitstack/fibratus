# Copyright 2015 by Nedim Sabic (RabbitStack)
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
from enum import Enum

from fibratus.common import NA
from fibratus.kevent_types import SEND_SOCKET_TCPV4, SEND_SOCKET_UDPV4, RECV_SOCKET_TCPV4, RECV_SOCKET_UDPV4, \
    ACCEPT_SOCKET_TCPV4, CONNECT_SOCKET_TCPV4, DISCONNECT_SOCKET_TCPV4, RECONNECT_SOCKET_TCPV4

import fibratus.tcpip.ports as ports


def port_to_proto(port, l4_proto):
    if 'TCP' in l4_proto:
        return ports.IANA_PORTS_TCP[port] if port in ports.IANA_PORTS_TCP else NA
    else:
        return ports.IANA_PORTS_UDP[port] if port in ports.IANA_PORTS_UDP else NA


class IpVer(Enum):

    IPV4 = 0
    IPV6 = 1


class TcpIpParser(object):

    def __init__(self, kevent):
        """TCP/IP kernel event parser.

        Packages the TCP and UDP requests into a single
        kernel event.

        Parameters:
        ----------

        kevent: dict
            kernel event representing the UDP / TCP request
        """
        self._kevent = kevent

    def parse_tcpip(self, ketype, ktcpip):
        """Parses the TCP/IP kernel events.

        Parameters
        ----------

        ketype: tuple
            network kernel event
        ktcpip:
            kevent payload as forwarded from the collector

        """
        pid = ktcpip.pid
        ip_src = ktcpip.saddr
        ip_dst = ktcpip.daddr
        sport = ktcpip.sport
        dport = ktcpip.dport

        self._kevent.pid = pid

        if ketype in [SEND_SOCKET_TCPV4,
                      SEND_SOCKET_UDPV4,
                      RECV_SOCKET_TCPV4,
                      RECV_SOCKET_UDPV4]:
            # get the application layer protocol
            # associated with the tcp segment
            # or the udp datagram
            if ketype in [SEND_SOCKET_TCPV4,
                          RECV_SOCKET_TCPV4]:
                l4_proto = 'TCP'
            else:
                l4_proto = 'UDP'
            protocol = port_to_proto(dport, l4_proto)
            if protocol == NA:
                protocol = port_to_proto(sport, l4_proto)
            self._kevent.params = {'pid': pid,
                                   'ip_src': ip_src,
                                   'ip_dst': ip_dst,
                                   'sport': sport,
                                   'dport': dport,
                                   'packet_size': ktcpip.size,
                                   'l4_proto': l4_proto,
                                   'protocol': protocol}
        elif ketype == ACCEPT_SOCKET_TCPV4:
            self._kevent.params = dict(pid=pid, ip_src=ip_src, ip_dst=ip_dst,
                                       sport=sport,
                                       dport=dport,
                                       rwin=ktcpip.rcvwin,
                                       protocol=port_to_proto(sport, 'TCP'))

        elif ketype == CONNECT_SOCKET_TCPV4:
            self._kevent.params = dict(pid=pid,
                                       ip_src=ip_src,
                                       ip_dst=ip_dst,
                                       sport=sport,
                                       dport=dport,
                                       rwin=ktcpip.rcvwin,
                                       protocol=port_to_proto(dport, 'TCP'))
        elif ketype == DISCONNECT_SOCKET_TCPV4:
            self._kevent.params = dict(pid=pid,
                                       ip_src=ip_src,
                                       ip_dst=ip_dst,
                                       sport=sport,
                                       dport=dport)

        elif ketype == RECONNECT_SOCKET_TCPV4:
            self._kevent.params = dict(pid=pid,
                                       ip_src=ip_src,
                                       ip_dst=ip_dst,
                                       sport=sport,
                                       dport=dport)
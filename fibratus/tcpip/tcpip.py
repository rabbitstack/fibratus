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

from _ctypes import byref
import subprocess
from enum import Enum
from pstreamc import PStreamCollector

from fibratus.apidefs.cdefs import ERROR_ALREADY_EXISTS
from fibratus.apidefs.etw import TRACEHANDLE, start_trace, enable_trace_ex, EVENT_CONTROL_CODE_ENABLE_PROVIDER, \
    control_trace, EVENT_TRACE_CONTROL_STOP, NDIS_LOGGER_NAME, NDIS_TRACE_CONTROL_GUID
from fibratus.common import NA
from fibratus.controller import PTraceProps
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
        self.pstreamc = PStreamCollector(NDIS_LOGGER_NAME.encode())

    def start_packet_flow(self):

        pprops = PTraceProps()
        pprops.logger_name = NDIS_LOGGER_NAME

        handle = TRACEHANDLE()
        status = start_trace(byref(handle),
                             NDIS_LOGGER_NAME,
                             pprops.get())
        if status == ERROR_ALREADY_EXISTS:
            control_trace(handle,
                          NDIS_LOGGER_NAME,
                          pprops.get(),
                          EVENT_TRACE_CONTROL_STOP)
            start_trace(byref(handle),
                        NDIS_LOGGER_NAME,
                        pprops.get())

        enable_trace_ex(handle, byref(NDIS_TRACE_CONTROL_GUID),
                        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                        5, 0,
                        0,
                        0,
                        None)
        # this attaches the NDIS mini filter driver
        # to the physical network adapter
        try:
            subprocess.check_output(['netsh', 'trace', 'start',
                                     'capture=yes', 'maxSize=1MB'],
                                    stderr=subprocess.STDOUT,
                                    shell=True)
        except subprocess.CalledProcessError as e:
            print(e.output, e.cmd, e.args)
        self.pstreamc.open_packet_flow(self.__on_next_packet)

    def stop_packet_flow(self):
        pass

    def __on_next_packet(self, layer, headers):
        print(layer, headers)

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


if __name__ == '__main__':
    parser = TcpIpParser(None)
    parser.start_packet_flow()

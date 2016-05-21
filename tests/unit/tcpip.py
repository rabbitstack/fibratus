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
from unittest.mock import Mock
import pytest
from fibratus.kevent import KEvent
from fibratus.kevent_types import SEND_SOCKET_TCPV4, SEND_SOCKET_UDPV4, RECV_SOCKET_TCPV4, RECV_SOCKET_UDPV4, \
    ACCEPT_SOCKET_TCPV4, CONNECT_SOCKET_TCPV4, DISCONNECT_SOCKET_TCPV4, RECONNECT_SOCKET_TCPV4
from fibratus.tcpip import TcpIpParser
from fibratus.common import DotD as dd


@pytest.fixture(scope='module')
def kevent_mock():
    return Mock(spec_set=KEvent)


@pytest.fixture(scope='module')
def tcpip_parser(kevent_mock):
    return TcpIpParser(kevent_mock)


class TestTcpIpParser():

    @pytest.mark.parametrize('ktcpip, l4_proto, l5_proto, kevent_type', [
        (dd({"saddr": "10.0.2.15", "sport": 49279, "daddr": "216.58.211.238",
             "dport": 443, "pid": 1848, "connid": 0, "size": 63, "seqnum": 0}), 'TCP', 'https', SEND_SOCKET_TCPV4),
        (dd({"saddr": "10.0.2.15", "sport": 49279, "daddr": "216.58.211.238",
             "dport": 53, "pid": 1848, "connid": 0, "size": 63, "seqnum": 0}), 'UDP', 'domain', SEND_SOCKET_UDPV4)])
    def test_parse_send(self, ktcpip, l4_proto, l5_proto,
                        kevent_type, tcpip_parser,
                        kevent_mock):

        tcpip_parser.parse_tcpip(kevent_type, ktcpip)
        kparams = kevent_mock.params

        assert kparams['pid'] == ktcpip.pid
        assert kparams['ip_src'] == ktcpip.saddr
        assert kparams['ip_dst'] == ktcpip.daddr
        assert kparams['sport'] == ktcpip.sport
        assert kparams['dport'] == ktcpip.dport
        assert kparams['packet_size'] == ktcpip.size
        assert kparams['l4_proto'] == l4_proto
        assert kparams['application'] == l5_proto

    @pytest.mark.parametrize('ktcpip, l4_proto, l5_proto, kevent_type', [
        (dd({'seqnum': 0, 'connid': 0, 'sport': 49720, 'daddr': '91.226.88.5',
             'saddr': '10.0.2.15', 'size': 266, 'pid': 1380, 'dport': 443}), 'TCP', 'https', RECV_SOCKET_TCPV4),
        (dd({"saddr": "10.0.2.15", "sport": 49279, "daddr": "216.58.211.238",
             "dport": 53, "pid": 1848, "connid": 0, "size": 63, "seqnum": 0}), 'UDP', 'domain', RECV_SOCKET_UDPV4)])
    def test_parse_recv(self, ktcpip, l4_proto, l5_proto,
                        kevent_type, tcpip_parser,
                        kevent_mock):

        tcpip_parser.parse_tcpip(kevent_type, ktcpip)
        kparams = kevent_mock.params

        assert kparams['pid'] == ktcpip.pid
        assert kparams['ip_src'] == ktcpip.saddr
        assert kparams['ip_dst'] == ktcpip.daddr
        assert kparams['sport'] == ktcpip.sport
        assert kparams['dport'] == ktcpip.dport
        assert kparams['packet_size'] == ktcpip.size
        assert kparams['l4_proto'] == l4_proto
        assert kparams['application'] == l5_proto

    def test_parse_recv_dport_na(self, tcpip_parser, kevent_mock):
        ktcpip = dd({'seqnum': 0, 'connid': 0, 'sport': 25, 'daddr': '91.226.88.5',
                    'saddr': '10.0.2.15', 'size': 266, 'pid': 1380, 'dport': 51234})
        tcpip_parser.parse_tcpip(RECV_SOCKET_TCPV4, ktcpip)
        kparams = kevent_mock.params
        assert kparams['application'] == 'smtp'

    def test_parse_accept(self, tcpip_parser, kevent_mock):
        ktcpip = dd({'connid': 0, 'sndwinscale': 0, 'rcvwinscale': 0, 'saddr': '10.0.2.15',
                     'sport': 22, 'rcvwin': 64240, 'tsopt': 0, 'pid': 1380, 'seqnum': 0,
                     'daddr': '216.58.211.206', 'size': 0, 'mss': 1460, 'dport': 49804, 'wsopt': 0, 'sackopt': 0})

        tcpip_parser.parse_tcpip(ACCEPT_SOCKET_TCPV4, ktcpip)
        kparams = kevent_mock.params

        assert kparams['pid'] == ktcpip.pid
        assert kparams['ip_src'] == ktcpip.saddr
        assert kparams['ip_dst'] == ktcpip.daddr
        assert kparams['sport'] == ktcpip.sport
        assert kparams['dport'] == ktcpip.dport
        assert kparams['rwin'] == ktcpip.rcvwin
        assert kparams['application'] == 'ssh'

    def test_parse_connect(self, tcpip_parser, kevent_mock):
        ktcpip = dd({'connid': 0, 'sndwinscale': 0, 'rcvwinscale': 0, 'saddr': '10.0.2.15',
                     'sport': 49804, 'rcvwin': 64240, 'tsopt': 0, 'pid': 1380, 'seqnum': 0,
                     'daddr': '216.58.211.206', 'size': 0, 'mss': 1460, 'dport': 443, 'wsopt': 0, 'sackopt': 0})

        tcpip_parser.parse_tcpip(CONNECT_SOCKET_TCPV4, ktcpip)
        kparams = kevent_mock.params

        assert kparams['pid'] == ktcpip.pid
        assert kparams['ip_src'] == ktcpip.saddr
        assert kparams['ip_dst'] == ktcpip.daddr
        assert kparams['sport'] == ktcpip.sport
        assert kparams['dport'] == ktcpip.dport
        assert kparams['rwin'] == ktcpip.rcvwin
        assert kparams['application'] == 'https'

    def test_parse_disconnect(self, tcpip_parser, kevent_mock):
        ktcpip = dd({'connid': 0, 'saddr': '10.0.2.15',
                     'sport': 49804, 'pid': 1380,
                     'daddr': '216.58.211.206', 'dport': 443,})

        tcpip_parser.parse_tcpip(DISCONNECT_SOCKET_TCPV4, ktcpip)
        kparams = kevent_mock.params

        assert kparams['pid'] == ktcpip.pid
        assert kparams['ip_src'] == ktcpip.saddr
        assert kparams['ip_dst'] == ktcpip.daddr
        assert kparams['sport'] == ktcpip.sport
        assert kparams['dport'] == ktcpip.dport

    def test_parse_reconnect(self, tcpip_parser, kevent_mock):
        ktcpip = dd({'connid': 0, 'saddr': '10.0.2.15',
                     'sport': 49804, 'pid': 1380,
                     'daddr': '216.58.211.206', 'dport': 443,})

        tcpip_parser.parse_tcpip(RECONNECT_SOCKET_TCPV4, ktcpip)
        kparams = kevent_mock.params

        assert kparams['pid'] == ktcpip.pid
        assert kparams['ip_src'] == ktcpip.saddr
        assert kparams['ip_dst'] == ktcpip.daddr
        assert kparams['sport'] == ktcpip.sport
        assert kparams['dport'] == ktcpip.dport






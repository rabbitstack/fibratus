/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
 * https://www.fibratus.io
 * All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package interceptors

import (
	"net"
	"time"

	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/network"
	"github.com/rabbitstack/fibratus/pkg/util/ports"
)

var (
	remappedKtypes = map[ktypes.Ktype]ktypes.Ktype{
		ktypes.AcceptTCPv4:     ktypes.Accept,
		ktypes.AcceptTCPv6:     ktypes.Accept,
		ktypes.ConnectTCPv4:    ktypes.Connect,
		ktypes.ConnectTCPv6:    ktypes.Connect,
		ktypes.ReconnectTCPv4:  ktypes.Reconnect,
		ktypes.ReconnectTCPv6:  ktypes.Reconnect,
		ktypes.RetransmitTCPv4: ktypes.Retransmit,
		ktypes.RetransmitTCPv6: ktypes.Retransmit,
		ktypes.DisconnectTCPv4: ktypes.Disconnect,
		ktypes.DisconnectTCPv6: ktypes.Disconnect,
		ktypes.SendTCPv4:       ktypes.Send,
		ktypes.SendTCPv6:       ktypes.Send,
		ktypes.SendUDPv4:       ktypes.Send,
		ktypes.SendUDPv6:       ktypes.Send,
		ktypes.RecvTCPv4:       ktypes.Recv,
		ktypes.RecvTCPv6:       ktypes.Recv,
		ktypes.RecvUDPv4:       ktypes.Recv,
		ktypes.RecvUDPv6:       ktypes.Recv,
	}
)

type netInterceptor struct {
	reverseDNS *network.ReverseDNS
}

// newNetInterceptor creates a new instance of the network kernel stream interceptor.
func newNetInterceptor() KstreamInterceptor {
	return &netInterceptor{
		reverseDNS: network.NewReverseDNS(2000, time.Minute*30, time.Minute*2),
	}
}

func (netInterceptor) Name() InterceptorType {
	return Net
}

func (n netInterceptor) Close() {
	n.reverseDNS.Close()
}

// Intercept overrides the kernel event type according to the transport layer
// and/or IP protocol version. At this point we also append the port names for all
// network kernel events and perform reverse DNS lookups to obtain the domain names.
func (n *netInterceptor) Intercept(kevt *kevent.Kevent) (*kevent.Kevent, bool, error) {
	if kevt.Category == ktypes.Net {
		if kevt.IsNetworkTCP() {
			kevt.Kparams.Append(kparams.NetL4Proto, kparams.Enum, network.TCP)
		}
		if kevt.IsNetworkUDP() {
			kevt.Kparams.Append(kparams.NetL4Proto, kparams.Enum, network.UDP)
		}

		n.resolvePortName(kevt)

		names := n.resolveNamesForIP(unwrapIP(kevt.Kparams.GetIP(kparams.NetDIP)))
		if len(names) > 0 {
			kevt.Kparams.Append(kparams.NetDIPNames, kparams.Slice, names)
		}

		names = n.resolveNamesForIP(unwrapIP(kevt.Kparams.GetIP(kparams.NetSIP)))
		if len(names) > 0 {
			kevt.Kparams.Append(kparams.NetSIPNames, kparams.Slice, names)
		}

		return remapKtype(kevt), false, nil
	}
	return kevt, true, nil
}

func (n *netInterceptor) resolveNamesForIP(ip net.IP) []string {
	names, err := n.reverseDNS.Add(network.AddressFromIP(ip))
	if err != nil {
		return nil
	}
	return names
}

// resolvePortName resolves the IANA service name for the particular port and transport protocol as
// per https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml.
func (n netInterceptor) resolvePortName(kevt *kevent.Kevent) *kevent.Kevent {
	dport := unwrapPort(kevt.Kparams.GetUint16(kparams.NetDport))
	sport := unwrapPort(kevt.Kparams.GetUint16(kparams.NetSport))

	if kevt.IsNetworkTCP() {
		if name, ok := ports.TCPPortNames[dport]; ok {
			kevt.Kparams.Append(kparams.NetDportName, kparams.AnsiString, name)
		}
		if name, ok := ports.TCPPortNames[sport]; ok {
			kevt.Kparams.Append(kparams.NetSportName, kparams.AnsiString, name)
		}
		return kevt
	}

	if name, ok := ports.UDPPortNames[dport]; ok {
		kevt.Kparams.Append(kparams.NetDportName, kparams.AnsiString, name)
	}
	if name, ok := ports.UDPPortNames[sport]; ok {
		kevt.Kparams.Append(kparams.NetSportName, kparams.AnsiString, name)
	}
	return kevt
}

func unwrapIP(ip net.IP, _ error) net.IP     { return ip }
func unwrapPort(port uint16, _ error) uint16 { return port }

func remapKtype(kevt *kevent.Kevent) *kevent.Kevent {
	ktyp, ok := remappedKtypes[kevt.Type]
	if !ok {
		return kevt
	}
	kevt.Type = ktyp
	return kevt
}

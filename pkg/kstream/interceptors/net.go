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
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/net"
	"github.com/rabbitstack/fibratus/pkg/util/ports"
)

type netInterceptor struct{}

// newNetInterceptor creates a new instance of the network kernel stream interceptor.
func newNetInterceptor() KstreamInterceptor {
	return &netInterceptor{}
}

func (netInterceptor) Name() InterceptorType {
	return Net
}

// Intercpet overrides the kernel event type according to the transport layer
// and/or IP protocol version. At this point we also append the port names for all
// network kernel events.
func (n *netInterceptor) Intercept(kevt *kevent.Kevent) (*kevent.Kevent, bool, error) {
	switch kevt.Type {
	case ktypes.AcceptTCPv4, ktypes.AcceptTCPv6:
		appendPortKparam(kevt, true)
		kevt.Type = ktypes.Accept
		return kevt, false, nil

	case ktypes.ConnectTCPv4, ktypes.ConnectTCPv6:
		appendPortKparam(kevt, true)
		kevt.Type = ktypes.Connect
		return kevt, false, nil

	case ktypes.ReconnectTCPv4, ktypes.ReconnectTCPv6:
		appendPortKparam(kevt, true)
		kevt.Type = ktypes.Reconnect
		return kevt, false, nil

	case ktypes.RetransmitTCPv4, ktypes.RetransmitTCPv6:
		appendPortKparam(kevt, true)
		kevt.Type = ktypes.Retransmit
		return kevt, false, nil

	case ktypes.DisconnectTCPv4, ktypes.DisconnectTCPv6:
		appendPortKparam(kevt, true)
		kevt.Type = ktypes.Disconnect
		return kevt, false, nil

	case ktypes.SendTCPv4, ktypes.SendTCPv6, ktypes.SendUDPv4, ktypes.SendUDPv6:
		// append Layer 4 protocol name to Send events
		if kevt.Type == ktypes.SendTCPv4 || kevt.Type == ktypes.SendTCPv6 {
			kevt.Kparams.Append(kparams.NetL4Proto, kparams.Enum, net.TCP)
		} else {
			kevt.Kparams.Append(kparams.NetL4Proto, kparams.Enum, net.UDP)
		}
		appendPortKparam(kevt, kevt.Type == ktypes.SendTCPv4 || kevt.Type == ktypes.SendTCPv6)
		kevt.Type = ktypes.Send
		return kevt, false, nil

	case ktypes.RecvTCPv4, ktypes.RecvTCPv6, ktypes.RecvUDPv4, ktypes.RecvUDPv6:
		// append Layer 4 protocol name to Recv events
		if kevt.Type == ktypes.RecvTCPv4 || kevt.Type == ktypes.RecvTCPv6 {
			kevt.Kparams.Append(kparams.NetL4Proto, kparams.Enum, net.TCP)
		} else {
			kevt.Kparams.Append(kparams.NetL4Proto, kparams.Enum, net.UDP)
		}
		appendPortKparam(kevt, kevt.Type == ktypes.RecvTCPv4 || kevt.Type == ktypes.RecvTCPv6)
		kevt.Type = ktypes.Recv
		return kevt, false, nil
	}

	return kevt, true, nil
}

// appendPortKparam resolves the IANA (https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)
// service name for the particular port and transport protocol.
func appendPortKparam(kevt *kevent.Kevent, isTCP bool) {
	dport, _ := kevt.Kparams.GetUint16(kparams.NetDport)
	sport, _ := kevt.Kparams.GetUint16(kparams.NetSport)
	if isTCP {
		if name, ok := ports.TCPPortNames[dport]; ok {
			kevt.Kparams.Append(kparams.NetDportName, kparams.AnsiString, name)
		}
		if name, ok := ports.TCPPortNames[sport]; ok {
			kevt.Kparams.Append(kparams.NetSportName, kparams.AnsiString, name)
		}
		return
	}
	if name, ok := ports.UDPPortNames[dport]; ok {
		kevt.Kparams.Append(kparams.NetDportName, kparams.AnsiString, name)
	}
	if name, ok := ports.UDPPortNames[sport]; ok {
		kevt.Kparams.Append(kparams.NetSportName, kparams.AnsiString, name)
	}
}

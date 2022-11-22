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

package processors

import (
	"net"
	"time"

	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/network"
	"github.com/rabbitstack/fibratus/pkg/util/ports"
)

type netProcessor struct {
	reverseDNS *network.ReverseDNS
}

// newNetProcessor creates a new instance of the network event interceptor.
func newNetProcessor() Processor {
	return &netProcessor{
		reverseDNS: network.NewReverseDNS(2000, time.Minute*30, time.Minute*2),
	}
}

func (netProcessor) Name() ProcessorType { return Net }

func (n netProcessor) Close() {
	n.reverseDNS.Close()
}

func (n *netProcessor) ProcessEvent(kevt *kevent.Kevent) (*kevent.Kevent, bool, error) {
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

		return kevt, false, nil
	}
	return kevt, true, nil
}

func (n *netProcessor) resolveNamesForIP(ip net.IP) []string {
	names, err := n.reverseDNS.Add(network.AddressFromIP(ip))
	if err != nil {
		return nil
	}
	return names
}

// resolvePortName resolves the IANA service name for the particular port and transport protocol as
// per https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml.
func (n netProcessor) resolvePortName(kevt *kevent.Kevent) *kevent.Kevent {
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

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
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/network"
	"github.com/rabbitstack/fibratus/pkg/util/ports"
)

type netProcessor struct {
}

// newNetProcessor creates a new instance of the network event interceptor.
func newNetProcessor() Processor {
	return &netProcessor{}
}

func (netProcessor) Name() ProcessorType { return Net }

func (n netProcessor) Close() {}

func (n *netProcessor) ProcessEvent(e *kevent.Kevent) (*kevent.Kevent, bool, error) {
	if e.Category == ktypes.Net {
		if e.IsNetworkTCP() && !e.IsDNS() {
			e.AppendEnum(kparams.NetL4Proto, uint32(network.TCP), network.ProtoNames)
		}
		if e.IsNetworkUDP() && !e.IsDNS() {
			e.AppendEnum(kparams.NetL4Proto, uint32(network.UDP), network.ProtoNames)
		}

		if e.IsDNS() {
			return e, false, nil
		}

		n.resolvePortName(e)

		return e, false, nil
	}
	return e, true, nil
}

// resolvePortName resolves the IANA service name for the particular port and transport protocol as
// per https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml.
func (n netProcessor) resolvePortName(e *kevent.Kevent) *kevent.Kevent {
	dport := e.Kparams.TryGetUint16(kparams.NetDport)
	sport := e.Kparams.TryGetUint16(kparams.NetSport)

	if e.IsNetworkTCP() {
		if name, ok := ports.TCPPortNames[dport]; ok {
			e.Kparams.Append(kparams.NetDportName, kparams.AnsiString, name)
		}
		if name, ok := ports.TCPPortNames[sport]; ok {
			e.Kparams.Append(kparams.NetSportName, kparams.AnsiString, name)
		}
		return e
	}

	if name, ok := ports.UDPPortNames[dport]; ok {
		e.Kparams.Append(kparams.NetDportName, kparams.AnsiString, name)
	}
	if name, ok := ports.UDPPortNames[sport]; ok {
		e.Kparams.Append(kparams.NetSportName, kparams.AnsiString, name)
	}
	return e
}

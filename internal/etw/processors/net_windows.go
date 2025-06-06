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
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
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

func (n *netProcessor) ProcessEvent(e *event.Event) (*event.Event, bool, error) {
	if e.Category == event.Net {
		if e.IsNetworkTCP() && !e.IsDNS() {
			e.AppendEnum(params.NetL4Proto, uint32(network.TCP), network.ProtoNames)
		}
		if e.IsNetworkUDP() && !e.IsDNS() {
			e.AppendEnum(params.NetL4Proto, uint32(network.UDP), network.ProtoNames)
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
func (n netProcessor) resolvePortName(e *event.Event) *event.Event {
	dport := e.Params.TryGetUint16(params.NetDport)
	sport := e.Params.TryGetUint16(params.NetSport)

	if e.IsNetworkTCP() {
		if name, ok := ports.TCPPortNames[dport]; ok {
			e.Params.Append(params.NetDportName, params.AnsiString, name)
		}
		if name, ok := ports.TCPPortNames[sport]; ok {
			e.Params.Append(params.NetSportName, params.AnsiString, name)
		}
		return e
	}

	if name, ok := ports.UDPPortNames[dport]; ok {
		e.Params.Append(params.NetDportName, params.AnsiString, name)
	}
	if name, ok := ports.UDPPortNames[sport]; ok {
		e.Params.Append(params.NetSportName, params.AnsiString, name)
	}
	return e
}

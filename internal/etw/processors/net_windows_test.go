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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net"
	"testing"
)

func TestNetworkProcessor(t *testing.T) {
	var tests = []struct {
		name       string
		e          *event.Event
		assertions func(*event.Event, *testing.T)
	}{
		{
			"send tcpv4",
			&event.Event{
				Type:     event.SendTCPv4,
				Category: event.Net,
				Params: event.Params{
					params.NetDport: {Name: params.NetDport, Type: params.Uint16, Value: uint16(443)},
					params.NetSport: {Name: params.NetSport, Type: params.Uint16, Value: uint16(43123)},
					params.NetSIP:   {Name: params.NetSIP, Type: params.IPv4, Value: net.ParseIP("127.0.0.1")},
					params.NetDIP:   {Name: params.NetDIP, Type: params.IPv4, Value: net.ParseIP("8.8.8.8")},
				},
			},
			func(e *event.Event, t *testing.T) {
				assert.Equal(t, "Send", e.Type.String())
				assert.Equal(t, "https", e.GetParamAsString(params.NetDportName))
				assert.Equal(t, "TCP", e.GetParamAsString(params.NetL4Proto))
				assert.Equal(t, "127.0.0.1", e.GetParamAsString(params.NetSIP))
				assert.Equal(t, "8.8.8.8", e.GetParamAsString(params.NetDIP))
				assert.Equal(t, "443", e.GetParamAsString(params.NetDport))
				assert.Equal(t, "43123", e.GetParamAsString(params.NetSport))
			},
		},
		{
			"recv udp6",
			&event.Event{
				Type:     event.RecvUDPv6,
				Category: event.Net,
				Params: event.Params{
					params.NetDport: {Name: params.NetDport, Type: params.Uint16, Value: uint16(53)},
					params.NetSport: {Name: params.NetSport, Type: params.Uint16, Value: uint16(43123)},
					params.NetSIP:   {Name: params.NetSIP, Type: params.IPv4, Value: net.ParseIP("127.0.0.1")},
					params.NetDIP:   {Name: params.NetDIP, Type: params.IPv4, Value: net.ParseIP("8.8.8.8")},
				},
			},
			func(e *event.Event, t *testing.T) {
				assert.Equal(t, "Recv", e.Type.String())
				assert.Equal(t, "domain", e.GetParamAsString(params.NetDportName))
				assert.Equal(t, "UDP", e.GetParamAsString(params.NetL4Proto))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newNetProcessor()
			var err error
			tt.e, _, err = p.ProcessEvent(tt.e)
			require.NoError(t, err)
			tt.assertions(tt.e, t)
		})
	}
}

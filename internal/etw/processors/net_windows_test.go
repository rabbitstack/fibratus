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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net"
	"testing"
)

func TestNetworkProcessor(t *testing.T) {
	var tests = []struct {
		name       string
		e          *kevent.Kevent
		assertions func(*kevent.Kevent, *testing.T)
	}{
		{
			"send tcpv4",
			&kevent.Kevent{
				Type:     ktypes.SendTCPv4,
				Category: ktypes.Net,
				Kparams: kevent.Kparams{
					kparams.NetDport: {Name: kparams.NetDport, Type: kparams.Uint16, Value: uint16(443)},
					kparams.NetSport: {Name: kparams.NetSport, Type: kparams.Uint16, Value: uint16(43123)},
					kparams.NetSIP:   {Name: kparams.NetSIP, Type: kparams.IPv4, Value: net.ParseIP("127.0.0.1")},
					kparams.NetDIP:   {Name: kparams.NetDIP, Type: kparams.IPv4, Value: net.ParseIP("8.8.8.8")},
				},
			},
			func(e *kevent.Kevent, t *testing.T) {
				assert.Equal(t, "Send", e.Type.String())
				assert.Equal(t, "https", e.GetParamAsString(kparams.NetDportName))
				assert.Equal(t, "TCP", e.GetParamAsString(kparams.NetL4Proto))
				assert.Equal(t, "127.0.0.1", e.GetParamAsString(kparams.NetSIP))
				assert.Equal(t, "8.8.8.8", e.GetParamAsString(kparams.NetDIP))
				assert.Equal(t, "443", e.GetParamAsString(kparams.NetDport))
				assert.Equal(t, "43123", e.GetParamAsString(kparams.NetSport))
			},
		},
		{
			"recv udp6",
			&kevent.Kevent{
				Type:     ktypes.RecvUDPv6,
				Category: ktypes.Net,
				Kparams: kevent.Kparams{
					kparams.NetDport: {Name: kparams.NetDport, Type: kparams.Uint16, Value: uint16(53)},
					kparams.NetSport: {Name: kparams.NetSport, Type: kparams.Uint16, Value: uint16(43123)},
					kparams.NetSIP:   {Name: kparams.NetSIP, Type: kparams.IPv4, Value: net.ParseIP("127.0.0.1")},
					kparams.NetDIP:   {Name: kparams.NetDIP, Type: kparams.IPv4, Value: net.ParseIP("8.8.8.8")},
				},
			},
			func(e *kevent.Kevent, t *testing.T) {
				assert.Equal(t, "Recv", e.Type.String())
				assert.Equal(t, "domain", e.GetParamAsString(kparams.NetDportName))
				assert.Equal(t, "UDP", e.GetParamAsString(kparams.NetL4Proto))
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

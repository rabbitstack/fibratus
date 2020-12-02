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
	knet "github.com/rabbitstack/fibratus/pkg/net"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net"
	"testing"
)

func TestNetInterceptorSend(t *testing.T) {
	kevt := &kevent.Kevent{
		Type: ktypes.SendTCPv4,
		Tid:  2484,
		PID:  859,
		Kparams: kevent.Kparams{
			kparams.NetDport: {Name: kparams.NetDport, Type: kparams.Uint16, Value: uint16(443)},
			kparams.NetSport: {Name: kparams.NetSport, Type: kparams.Uint16, Value: uint16(43123)},
			kparams.NetSIP:   {Name: kparams.NetSIP, Type: kparams.IPv4, Value: net.ParseIP("127.0.0.1")},
			kparams.NetDIP:   {Name: kparams.NetDIP, Type: kparams.IPv4, Value: net.ParseIP("216.58.201.174")},
		},
	}
	ni := newNetInterceptor()

	_, _, err := ni.Intercept(kevt)
	require.NoError(t, err)

	assert.Equal(t, ktypes.Send, kevt.Type)

	assert.Contains(t, kevt.Kparams, kparams.NetDportName)
	dportName, err := kevt.Kparams.GetString(kparams.NetDportName)
	require.NoError(t, err)
	assert.Equal(t, "https", dportName)

	v, err := kevt.Kparams.Get(kparams.NetL4Proto)
	require.NoError(t, err)
	assert.IsType(t, knet.L4Proto(1), v)
	assert.Equal(t, "tcp", v.(knet.L4Proto).String())

	sip, err := kevt.Kparams.GetIPv4(kparams.NetSIP)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", sip.String())

	dip, err := kevt.Kparams.GetIPv4(kparams.NetDIP)
	require.NoError(t, err)
	assert.Equal(t, "216.58.201.174", dip.String())
}

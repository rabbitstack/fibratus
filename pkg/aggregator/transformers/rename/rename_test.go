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

package rename

import (
	"github.com/rabbitstack/fibratus/pkg/aggregator/transformers"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net"
	"testing"
)

func TestTransform(t *testing.T) {
	evt := &event.Event{
		Type: event.SendTCPv4,
		Tid:  2484,
		PID:  859,
		Params: event.Params{
			params.NetDport: {Name: params.NetDport, Type: params.Uint16, Value: uint16(443)},
			params.NetSport: {Name: params.NetSport, Type: params.Uint16, Value: uint16(43123)},
			params.NetSIP:   {Name: params.NetSIP, Type: params.IPv4, Value: net.ParseIP("127.0.0.1")},
			params.NetDIP:   {Name: params.NetDIP, Type: params.IPv4, Value: net.ParseIP("216.58.201.174")},
		},
		Metadata: make(map[event.MetadataKey]any),
	}

	transf, err := transformers.Load(transformers.Config{Type: transformers.Rename, Transformer: Config{Params: []Rename{{Old: "dport", New: "dstport"}, {Old: "sip", New: "srcip"}}}})
	require.NoError(t, err)

	require.NoError(t, transf.Transform(evt))

	assert.True(t, evt.Params.Contains("dstport"))
	assert.False(t, evt.Params.Contains("dport"))
	assert.True(t, evt.Params.Contains("srcip"))
	assert.False(t, evt.Params.Contains("sip"))
}

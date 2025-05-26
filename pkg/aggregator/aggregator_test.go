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

package aggregator

import (
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/outputs"
	"github.com/rabbitstack/fibratus/pkg/outputs/console"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net"
	"testing"
	"time"
)

func TestNewBufferedAggregator(t *testing.T) {
	eventsc := make(chan *event.Event, 20)
	errsc := make(chan error, 1)
	agg, err := NewBuffered(
		eventsc,
		errsc,
		Config{FlushPeriod: time.Millisecond * 200},
		outputs.Config{Type: outputs.Console, Output: console.Config{Format: "pretty"}},
		nil,
		nil,
	)
	require.NoError(t, err)
	require.NotNil(t, agg)

	for i := 0; i < 4; i++ {
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
		}
		eventsc <- evt
	}
	<-time.After(time.Millisecond * 275)
	assert.Equal(t, int64(4), batchEvents.Value())

	for i := 0; i < 2; i++ {
		evt := &event.Event{
			Type: event.SendTCPv4,
			Tid:  2484,
			PID:  859,
			Seq:  uint64(i),
			Params: event.Params{
				params.NetDport: {Name: params.NetDport, Type: params.Uint16, Value: uint16(443)},
				params.NetSport: {Name: params.NetSport, Type: params.Uint16, Value: uint16(43123)},
				params.NetSIP:   {Name: params.NetSIP, Type: params.IPv4, Value: net.ParseIP("127.0.0.1")},
				params.NetDIP:   {Name: params.NetDIP, Type: params.IPv4, Value: net.ParseIP("216.58.201.174")},
			},
		}
		eventsc <- evt
	}
	<-time.After(time.Millisecond * 260)
	assert.Equal(t, int64(6), batchEvents.Value())
	assert.Equal(t, int64(2), flushesCount.Value())
}

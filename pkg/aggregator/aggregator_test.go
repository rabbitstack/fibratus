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
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/outputs"
	"github.com/rabbitstack/fibratus/pkg/outputs/console"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net"
	"testing"
	"time"
)

func TestNewBufferedAggregator(t *testing.T) {
	keventsc := make(chan *kevent.Kevent, 20)
	errsc := make(chan error, 1)
	agg, err := NewBuffered(
		keventsc,
		errsc,
		Config{FlushPeriod: time.Millisecond * 200},
		outputs.Config{Type: outputs.Console, Output: console.Config{Format: "pretty"}},
		nil,
		nil,
	)
	require.NoError(t, err)
	require.NotNil(t, agg)

	for i := 0; i < 4; i++ {
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
		keventsc <- kevt
	}
	<-time.After(time.Millisecond * 275)
	assert.Equal(t, int64(4), batchEvents.Value())

	for i := 0; i < 2; i++ {
		kevt := &kevent.Kevent{
			Type: ktypes.SendTCPv4,
			Tid:  2484,
			PID:  859,
			Seq:  uint64(i),
			Kparams: kevent.Kparams{
				kparams.NetDport: {Name: kparams.NetDport, Type: kparams.Uint16, Value: uint16(443)},
				kparams.NetSport: {Name: kparams.NetSport, Type: kparams.Uint16, Value: uint16(43123)},
				kparams.NetSIP:   {Name: kparams.NetSIP, Type: kparams.IPv4, Value: net.ParseIP("127.0.0.1")},
				kparams.NetDIP:   {Name: kparams.NetDIP, Type: kparams.IPv4, Value: net.ParseIP("216.58.201.174")},
			},
		}
		keventsc <- kevt
	}
	<-time.After(time.Millisecond * 260)
	assert.Equal(t, int64(6), batchEvents.Value())
	assert.Equal(t, int64(2), flushesCount.Value())
}

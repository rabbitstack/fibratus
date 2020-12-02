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

package tags

import (
	"github.com/rabbitstack/fibratus/pkg/aggregator/transformers"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net"
	"os"
	"testing"
)

func TestTransform(t *testing.T) {
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
		Metadata: make(map[string]string),
	}
	require.NoError(t, os.Setenv("NODENAME", "archbunny"))
	transf, err := transformers.Load(transformers.Config{Type: transformers.Tags, Transformer: Config{Tags: []Tag{{Key: "env", Value: "staging"}, {Key: "zone", Value: "dmz"}, {Key: "node", Value: "%NODENAME%"}}}})
	require.NoError(t, err)

	require.NoError(t, transf.Transform(kevt))

	require.Len(t, kevt.Metadata, 3)
	require.Contains(t, kevt.Metadata, "env")

	assert.Equal(t, "dmz", kevt.Metadata["zone"])

	assert.Equal(t, "archbunny", kevt.Metadata["node"])
}

/*
 * Copyright 2020-2021 by Nedim Sabic Sabic
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

package network

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net"
	"testing"
	"time"
)

func TestLookupAddr(t *testing.T) {
	reverseDNS := NewReverseDNS(100, time.Minute, time.Minute)
	names, err := reverseDNS.Add(AddressFromIP(net.ParseIP("8.8.8.8")))

	require.NoError(t, err)
	assert.Contains(t, names, "dns.google.")
	assert.Equal(t, int64(1), totalDNSLookups.Value())

	names, err = reverseDNS.Add(AddressFromIP(net.ParseIP("8.8.8.8")))
	require.NoError(t, err)
	assert.Contains(t, names, "dns.google.")
	assert.Equal(t, int64(1), totalDNSLookups.Value())
}

func TestLookupAddrExpiration(t *testing.T) {
	reverseDNS := NewReverseDNS(100, time.Millisecond*5, time.Minute)
	names, err := reverseDNS.Add(AddressFromIP(net.ParseIP("8.8.8.8")))

	require.NoError(t, err)
	assert.Contains(t, names, "dns.google.")
	assert.Equal(t, int64(1), totalDNSLookups.Value())

	time.Sleep(time.Millisecond * 10)
	reverseDNS.Expire()

	names, err = reverseDNS.Add(AddressFromIP(net.ParseIP("8.8.8.8")))
	require.NoError(t, err)
	assert.Contains(t, names, "dns.google.")
	assert.Equal(t, int64(2), totalDNSLookups.Value())
}

func TestTickerExpiration(t *testing.T) {
	reverseDNS := NewReverseDNS(100, time.Millisecond*50, time.Millisecond*100)

	names, err := reverseDNS.Add(AddressFromIP(net.ParseIP("8.8.8.8")))
	require.NoError(t, err)
	assert.Contains(t, names, "dns.google.")
	assert.Equal(t, int64(1), totalDNSLookups.Value())
	assert.True(t, reverseDNS.Len() == 1)

	time.Sleep(time.Millisecond * 105)

	assert.Empty(t, reverseDNS.Get(AddressFromIP(net.ParseIP("8.8.8.8"))))
	assert.True(t, reverseDNS.Len() == 0)
}

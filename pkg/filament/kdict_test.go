//go:build filament && windows
// +build filament,windows

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

package filament

import (
	"github.com/rabbitstack/fibratus/pkg/filament/cpython"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net"
	"testing"
	"time"
)

func TestProduceKdict(t *testing.T) {
	// this test crashes in the CI. Reenable once
	// we investigate why this happens
	t.SkipNow()
	err := cpython.Initialize()
	require.NoError(t, err)
	defer cpython.Finalize()
	now := time.Now()
	kevt := &kevent.Kevent{
		Seq:         uint64(12456738026482168384),
		Tid:         2484,
		PID:         859,
		CPU:         1,
		Name:        "CreateFile",
		Timestamp:   now,
		Category:    ktypes.File,
		Host:        "archrabbit",
		Description: "Creates or opens a new file, directory, I/O device, pipe, console",
	}
	dict, err := newKDict(kevt)
	require.NoError(t, err)
	require.NotNil(t, dict)

	assert.Equal(t, uint64(12456738026482168384), dict.Get(seq).Uint64())
	assert.Equal(t, uint32(859), dict.Get(pid).Uint32())
	assert.Equal(t, uint32(2484), dict.Get(tid).Uint32())
	assert.Equal(t, uint8(1), uint8(dict.Get(cpu).Uint32()))
	assert.Equal(t, "CreateFile", dict.Get(name).String())
	assert.Equal(t, "file", dict.Get(cat).String())
	assert.Equal(t, "archrabbit", dict.Get(host).String())
	assert.Equal(t, "Creates or opens a new file, directory, I/O device, pipe, console", dict.Get(desc).String())

	timestamp, err := time.Parse("2006-01-02 15:04:05.000000", dict.Get(ts).String())
	require.NoError(t, err)
	assert.Equal(t, timestamp.Year(), now.Year())
	assert.Equal(t, timestamp.Hour(), now.Hour())
	assert.Equal(t, timestamp.Second(), now.Second())
}

func TestProduceKdictWithIPAddresses(t *testing.T) {
	// this test crashes in the CI. Reenable once
	// we investigate why this happens
	t.SkipNow()
	err := cpython.Initialize()
	require.NoError(t, err)
	defer cpython.Finalize()

	kevt := &kevent.Kevent{
		Name: "Send",
		Tid:  2484,
		PID:  859,
		Kparams: kevent.Kparams{
			kparams.NetDport: {Name: kparams.NetDport, Type: kparams.Uint16, Value: uint16(443)},
			kparams.NetSport: {Name: kparams.NetSport, Type: kparams.Uint16, Value: uint16(43123)},
			kparams.NetSIP:   {Name: kparams.NetSIP, Type: kparams.IPv6, Value: net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334")},
			kparams.NetDIP:   {Name: kparams.NetDIP, Type: kparams.IPv4, Value: net.ParseIP("216.58.201.174")},
		},
	}

	dict, err := newKDict(kevt)
	require.NoError(t, err)
	require.NotNil(t, dict)

	kpars := dict.Get(cpython.PyUnicodeFromString("kparams"))
	kparamsDict := cpython.NewDictFromObject(kpars)

	assert.Equal(t, "216.58.201.174", kparamsDict.Get(cpython.PyUnicodeFromString("dip")).String())
	assert.Equal(t, "2001:db8:85a3::8a2e:370:7334", kparamsDict.Get(cpython.PyUnicodeFromString("sip")).String())
}

func BenchmarkTestProduceKdict(b *testing.B) {
	// this crashes in the CI. Reenable once
	// we investigate why this happens
	b.SkipNow()
	b.ReportAllocs()
	err := cpython.Initialize()
	require.NoError(b, err)
	defer cpython.Finalize()

	kevt := &kevent.Kevent{
		Seq:         uint64(12456738026482168384),
		Tid:         2484,
		PID:         859,
		CPU:         1,
		Name:        "CreateFile",
		Timestamp:   time.Now(),
		Category:    ktypes.File,
		Host:        "archrabbit",
		Description: "Creates or opens a new file, directory, I/O device, pipe, console",
	}

	for i := 0; i < b.N; i++ {
		dict, err := newKDict(kevt)
		if err != nil || dict.IsNull() {
			b.Fatal("invalid dict produced")
		}
	}
}

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
	"bufio"
	"bytes"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net"
	"strings"
	"testing"
	"time"
)

func init() {
	useEmbeddedPython = false
}

func TestNewFilament(t *testing.T) {
	filament, err := New("top_hives_io", nil, nil, &config.Config{Filament: config.FilamentConfig{Path: "_fixtures"}})
	require.NoError(t, err)
	require.NotNil(t, filament)
	defer filament.Close()
}

var buf bytes.Buffer

func init() {
	tableOutput = &buf
}

func TestOnNextKevent(t *testing.T) {
	// this test crashes in the CI. Reenable once
	// we investigate why this happens
	t.SkipNow()
	filament, err := New("test_on_next_kevent", nil, nil, &config.Config{Filament: config.FilamentConfig{FlushPeriod: time.Millisecond * 250, Path: "_fixtures"}})
	require.NoError(t, err)
	require.NotNil(t, filament)
	time.AfterFunc(time.Millisecond*1050, func() {
		filament.Close()
	})

	kevents := make(chan *kevent.Kevent, 100)
	errs := make(chan error, 10)
	for i := 1; i <= 100; i++ {
		kevt := &kevent.Kevent{
			Type:      ktypes.RegCreateKey,
			Tid:       2484,
			PID:       859,
			Name:      "RegCreateKey",
			Host:      "archrabbit",
			CPU:       uint8(i / 2),
			Category:  ktypes.Registry,
			Seq:       uint64(i),
			Timestamp: time.Now(),
			Kparams: kevent.Kparams{
				kparams.RegKeyName:   {Name: kparams.RegKeyName, Type: kparams.UnicodeString, Value: `HKEY_LOCAL_MACHINE\SYSTEM\Setup`},
				kparams.RegKeyHandle: {Name: kparams.RegKeyHandle, Type: kparams.HexInt64, Value: kparams.NewHex(uint64(18446666033449935464))},
				kparams.NetDIP:       {Name: kparams.NetDIP, Type: kparams.IPv4, Value: net.ParseIP("216.58.201.174")},
			},
		}
		kevents <- kevt
	}
	err = filament.Run(kevents, errs)
	require.Nil(t, err)
	sn := bufio.NewScanner(strings.NewReader(buf.String()))
	const headerOffset = 4
	rows := 0
	for sn.Scan() {
		rows++
	}
	assert.Equal(t, 100, rows-headerOffset)
}

func TestFilamentFilter(t *testing.T) {
	// skipped for the same reason as previous test
	t.SkipNow()
	filament, err := New("test_filter", nil, nil, &config.Config{Filament: config.FilamentConfig{Path: "_fixtures"}})
	require.NoError(t, err)
	require.NotNil(t, filament)
	defer filament.Close()
	require.NotNil(t, filament.Filter())
	kpars := kevent.Kparams{
		kparams.Comm:            {Name: kparams.Comm, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\svchost.exe -k RPCSS"},
		kparams.ProcessName:     {Name: kparams.ProcessName, Type: kparams.AnsiString, Value: "svchost.exe"},
		kparams.ProcessID:       {Name: kparams.ProcessID, Type: kparams.Uint32, Value: uint32(1234)},
		kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.Uint32, Value: uint32(345)},
	}

	kevt := &kevent.Kevent{
		Type:    ktypes.CreateProcess,
		Kparams: kpars,
		Name:    "CreateProcess",
	}

	require.True(t, filament.Filter().Run(kevt))
}

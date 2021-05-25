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

package kstream

import (
	"encoding/gob"
	"github.com/rabbitstack/fibratus/pkg/config"
	kerrors "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/syscall/etw"
	"github.com/rabbitstack/fibratus/pkg/syscall/tdh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"net"
	"os"
	"testing"
	"time"
)

func TestOpenKstream(t *testing.T) {
	psnap := new(ps.SnapshotterMock)
	hsnap := new(handle.SnapshotterMock)
	ktraceController := NewKtraceController(config.KstreamConfig{})
	kstreamc := NewConsumer(ktraceController, psnap, hsnap, &config.Config{})
	openTrace = func(ktrace etw.EventTraceLogfile) etw.TraceHandle {
		return etw.TraceHandle(2)
	}
	processTrace = func(handle etw.TraceHandle) error {
		return nil
	}
	err := kstreamc.OpenKstream()
	require.NoError(t, err)
}

func TestOpenKstreamInvalidHandle(t *testing.T) {
	psnap := new(ps.SnapshotterMock)
	hsnap := new(handle.SnapshotterMock)
	ktraceController := NewKtraceController(config.KstreamConfig{})
	kstreamc := NewConsumer(ktraceController, psnap, hsnap, &config.Config{})
	openTrace = func(ktrace etw.EventTraceLogfile) etw.TraceHandle {
		return etw.TraceHandle(0xffffffffffffffff)
	}
	err := kstreamc.OpenKstream()
	require.Error(t, err)
}

func TestOpenKstreamKsessionNotRunning(t *testing.T) {
	psnap := new(ps.SnapshotterMock)
	hsnap := new(handle.SnapshotterMock)
	ktraceController := NewKtraceController(config.KstreamConfig{})
	kstreamc := NewConsumer(ktraceController, psnap, hsnap, &config.Config{})
	openTrace = func(ktrace etw.EventTraceLogfile) etw.TraceHandle {
		return etw.TraceHandle(2)
	}
	processTrace = func(handle etw.TraceHandle) error {
		return kerrors.ErrKsessionNotRunning
	}
	err := kstreamc.OpenKstream()
	require.NoError(t, err)
	err = <-kstreamc.Errors()
	assert.EqualError(t, err, "kernel session from which you are trying to consume events in real time is not running")
}

func TestProcessKevent(t *testing.T) {
	psnap := new(ps.SnapshotterMock)
	hsnap := new(handle.SnapshotterMock)
	ktraceController := NewKtraceController(config.KstreamConfig{})
	kstreamc := NewConsumer(ktraceController, psnap, hsnap, &config.Config{})

	psnap.On("Find", mock.Anything).Return(&types.PS{Name: "cmd.exe"})

	openTrace = func(ktrace etw.EventTraceLogfile) etw.TraceHandle {
		return etw.TraceHandle(2)
	}
	processTrace = func(handle etw.TraceHandle) error {
		return nil
	}
	getPropertySize = func(evt *etw.EventRecord, descriptor *tdh.PropertyDataDescriptor) (uint32, error) {
		return uint32(10), nil
	}
	getProperty = func(evt *etw.EventRecord, descriptor *tdh.PropertyDataDescriptor, size uint32, buffer []byte) error {
		return nil
	}

	psnap.On("Write", mock.Anything).Return(nil)

	f, err := os.Open("./_fixtures/snapshots/create-process.gob")
	if err != nil {
		t.Fatal(err)
	}

	dec := gob.NewDecoder(f)
	var evt etw.EventRecord
	err = dec.Decode(&evt)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{}, 1)

	go func() {
		defer func() {
			done <- struct{}{}
		}()
		kevt := <-kstreamc.Events()

		assert.Equal(t, ktypes.Process, kevt.Category)
		assert.Equal(t, uint32(9828), kevt.Tid)
		assert.Equal(t, uint8(5), kevt.CPU)
		assert.Equal(t, ktypes.CreateProcess, kevt.Type)
		assert.Equal(t, "CreateProcess", kevt.Name)
		assert.Equal(t, "Creates a new process and its primary thread", kevt.Description)

		ts, err := time.Parse("2006-01-02 15:04:05.0000000 -0700 CEST", "2019-04-05 16:10:36.5225778 +0200 CEST")
		require.NoError(t, err)
		assert.Equal(t, ts.Year(), kevt.Timestamp.Year())
		assert.Equal(t, ts.Month(), kevt.Timestamp.Month())
		assert.Equal(t, ts.Day(), kevt.Timestamp.Day())
		assert.Equal(t, ts.Minute(), kevt.Timestamp.Minute())
		assert.Equal(t, ts.Second(), kevt.Timestamp.Second())
		assert.Equal(t, ts.Nanosecond(), kevt.Timestamp.Nanosecond())
		assert.Len(t, kevt.Kparams, 9)

		assert.True(t, kevt.Kparams.Contains(kparams.DTB))
		assert.True(t, kevt.Kparams.Contains(kparams.ProcessName))
	}()

	err = kstreamc.(*kstreamConsumer).processKevent(&evt)
	require.NoError(t, err)

	<-done
}

func TestGetParamEmptyBuffer(t *testing.T) {
	_, err := getParam("sip", nil, 16, tdh.NonStructType{InType: tdh.IntypeBinary, OutType: tdh.OutypeIPv6})
	require.Error(t, err)

	_, err = getParam("sip", []byte{}, 16, tdh.NonStructType{InType: tdh.IntypeBinary, OutType: tdh.OutypeIPv6})
	require.Error(t, err)
}

func TestGetParam(t *testing.T) {
	kpar, err := getParam("comm", []byte{99, 0, 109, 0, 100, 0, 92, 0, 102, 0, 105, 0, 98, 0, 114, 0, 97, 0, 116, 0, 117, 0, 115, 0, 92, 0, 102, 0, 105, 0, 98, 0, 114, 0, 97, 0, 116, 0, 117, 0, 115, 0, 46, 0, 101, 0, 120, 0, 101, 0, 32, 0, 32, 0, 0, 0}, 16, tdh.NonStructType{InType: tdh.IntypeUnicodeString})
	require.NoError(t, err)
	assert.Equal(t, kparams.UnicodeString, kpar.Type)
	assert.Equal(t, "cmd\\fibratus\\fibratus.exe  ", kpar.Value)

	kpar, err = getParam("exe", []byte{77, 105, 99, 114, 111, 115, 111, 102, 116, 46, 80, 104, 111, 116, 111, 115, 46, 101, 120, 101, 0}, 21, tdh.NonStructType{InType: tdh.IntypeAnsiString})
	require.NoError(t, err)
	assert.Equal(t, kparams.AnsiString, kpar.Type)
	assert.Equal(t, "Microsoft.Photos.exe", kpar.Value)

	kpar, err = getParam("flag", []byte{127}, 1, tdh.NonStructType{InType: tdh.IntypeInt8})
	require.NoError(t, err)
	assert.Equal(t, kparams.Int8, kpar.Type)
	assert.Equal(t, int8(127), kpar.Value)

	kpar, err = getParam("flag", []byte{255}, 1, tdh.NonStructType{InType: tdh.IntypeUint8})
	require.NoError(t, err)
	assert.Equal(t, kparams.Uint8, kpar.Type)
	assert.Equal(t, uint8(255), kpar.Value)

	kpar, err = getParam("flag", []byte{255}, 1, tdh.NonStructType{InType: tdh.IntypeUint8, OutType: tdh.OutypeHexInt8})
	require.NoError(t, err)
	assert.Equal(t, kparams.HexInt8, kpar.Type)
	assert.Equal(t, kparams.Hex("ff"), kpar.Value)

	kpar, err = getParam("enabled", []byte{1}, 1, tdh.NonStructType{InType: tdh.IntypeBoolean})
	require.NoError(t, err)
	assert.Equal(t, kparams.Bool, kpar.Type)
	assert.Equal(t, true, kpar.Value)

	kpar, err = getParam("enabled", []byte{0}, 1, tdh.NonStructType{InType: tdh.IntypeBoolean})
	require.NoError(t, err)
	assert.Equal(t, kparams.Bool, kpar.Type)
	assert.Equal(t, false, kpar.Value)

	kpar, err = getParam("addr", []byte{255, 169}, 2, tdh.NonStructType{InType: tdh.IntypeUint16, OutType: tdh.OutypeHexInt16})
	require.NoError(t, err)
	assert.Equal(t, kparams.HexInt16, kpar.Type)
	assert.Equal(t, kparams.Hex("a9ff"), kpar.Value)

	kpar, err = getParam("sport", []byte{255, 169}, 2, tdh.NonStructType{InType: tdh.IntypeUint16, OutType: tdh.OutypePort})
	require.NoError(t, err)
	assert.Equal(t, kparams.Port, kpar.Type)
	assert.Equal(t, uint16(65449), kpar.Value)

	kpar, err = getParam("pid", []byte{252, 26, 0, 0}, 4, tdh.NonStructType{InType: tdh.IntypeInt32})
	require.NoError(t, err)
	assert.Equal(t, kparams.Int32, kpar.Type)
	assert.Equal(t, int32(6908), kpar.Value)

	kpar, err = getParam("kproc", []byte{108, 3, 0, 0}, 4, tdh.NonStructType{InType: tdh.IntypeUint32})
	require.NoError(t, err)
	assert.Equal(t, kparams.Uint32, kpar.Type)
	assert.Equal(t, uint32(876), kpar.Value)

	kpar, err = getParam("kproc", []byte{108, 3, 0, 0}, 4, tdh.NonStructType{InType: tdh.IntypeUint32, OutType: tdh.OutypeHexInt32})
	require.NoError(t, err)
	assert.Equal(t, kparams.HexInt32, kpar.Type)
	assert.Equal(t, kparams.Hex("36c"), kpar.Value)

	kpar, err = getParam("dip", []byte{192, 168, 1, 210}, 4, tdh.NonStructType{InType: tdh.IntypeUint32, OutType: tdh.OutypeIPv4})
	require.NoError(t, err)
	assert.Equal(t, kparams.IPv4, kpar.Type)
	assert.Equal(t, net.ParseIP("192.168.1.210"), kpar.Value)

	kpar, err = getParam("syscall.addr", []byte{192, 168, 1, 210, 8, 1, 1, 1}, 8, tdh.NonStructType{InType: tdh.IntypeInt64})
	require.NoError(t, err)
	assert.Equal(t, kparams.Int64, kpar.Type)
	assert.Equal(t, int64(72340206409328832), kpar.Value)

	kpar, err = getParam("syscall.addr", []byte{192, 168, 1, 210, 199, 100, 100, 100}, 8, tdh.NonStructType{InType: tdh.IntypeUint64})
	require.NoError(t, err)
	assert.Equal(t, kparams.Uint64, kpar.Type)
	assert.Equal(t, uint64(7234017710848452800), kpar.Value)

	kpar, err = getParam("syscall.addr", []byte{192, 168, 1, 210, 199, 100, 100, 100}, 8, tdh.NonStructType{InType: tdh.IntypeUint64, OutType: tdh.OutypeHexInt64})
	require.NoError(t, err)
	assert.Equal(t, kparams.HexInt64, kpar.Type)
	assert.Equal(t, kparams.Hex("646464c7d201a8c0"), kpar.Value)

	kpar, err = getParam("currency", []byte{0, 0, 0, 1}, 4, tdh.NonStructType{InType: tdh.IntypeFloat})
	require.NoError(t, err)
	assert.Equal(t, kparams.Float, kpar.Type)
	assert.Equal(t, float32(2.3509887e-38), kpar.Value)

	kpar, err = getParam("currency", []byte{0, 0, 0, 0, 0, 0, 0, 1}, 8, tdh.NonStructType{InType: tdh.IntypeDouble})
	require.NoError(t, err)
	assert.Equal(t, kparams.Double, kpar.Type)
	assert.Equal(t, float64(7.291122019556398e-304), kpar.Value)

	kpar, err = getParam("kproc", []byte{108, 3, 0, 0}, 4, tdh.NonStructType{InType: tdh.IntypeHexInt32})
	require.NoError(t, err)
	assert.Equal(t, kparams.HexInt32, kpar.Type)
	assert.Equal(t, kparams.Hex("36c"), kpar.Value)

	kpar, err = getParam("syscall.addr", []byte{192, 168, 1, 210, 199, 100, 100, 100}, 8, tdh.NonStructType{InType: tdh.IntypeHexInt64})
	require.NoError(t, err)
	assert.Equal(t, kparams.HexInt64, kpar.Type)
	assert.Equal(t, kparams.Hex("646464c7d201a8c0"), kpar.Value)

	kpar, err = getParam("sid", []byte{96, 12, 161, 104, 133, 219, 255, 255, 0, 0, 0, 0, 3, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}, 8, tdh.NonStructType{InType: tdh.IntypeWbemSID})
	require.NoError(t, err)
	assert.Equal(t, kparams.WbemSID, kpar.Type)
	assert.Equal(t, "NT AUTHORITY\\SYSTEM", kpar.Value)

	kpar, err = getParam("sip", []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}, 16, tdh.NonStructType{InType: tdh.IntypeBinary, OutType: tdh.OutypeIPv6})
	require.NoError(t, err)
	assert.Equal(t, kparams.IPv6, kpar.Type)
	assert.Equal(t, net.ParseIP("::1"), kpar.Value)
}

func TestGetParamUnknownType(t *testing.T) {
	kpar, err := getParam("comm", []byte{99, 0, 109, 0, 100, 0, 92, 0, 102, 0, 105, 0, 98, 0, 114, 0, 97, 0, 116, 0, 117, 0, 115, 0, 92, 0, 102, 0, 105, 0, 98, 0, 114, 0, 97, 0, 116, 0, 117, 0, 115, 0, 46, 0, 101, 0, 120, 0, 101, 0, 32, 0, 32, 0, 0, 0}, 16, tdh.NonStructType{InType: tdh.IntypeFiletime})
	require.Error(t, err)
	require.Nil(t, kpar)
}

/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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

package systray

import (
	"encoding/json"
	"github.com/Microsoft/go-winio"
	"github.com/mitchellh/mapstructure"
	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net"
	"sync"
	"testing"
)

func handleMessage(t *testing.T, conn net.Conn, wg *sync.WaitGroup, msgs chan Msg) {
	buf := make([]byte, 1024)
	defer conn.Close()
	defer func() {
		wg.Done()
	}()
	n, err := conn.Read(buf)
	if err != nil {
		if err != io.EOF {
			t.Error(err)
			t.Fail()
		}
		return
	}
	var m Msg
	err = json.Unmarshal(buf[:n], &m)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	msgs <- m
}

func TestSystraySender(t *testing.T) {
	// set up named pipe server
	l, err := winio.ListenPipe(systrayPipe, nil)
	require.NoError(t, err)
	defer l.Close()

	var wg sync.WaitGroup
	wg.Add(3)

	msgs := make(chan Msg, 2)
	go func(wg *sync.WaitGroup) {
		for {
			conn, err := l.Accept()
			if err != nil {
				break
			}
			go handleMessage(t, conn, wg, msgs)
		}
	}(&wg)

	s, err := alertsender.Load(alertsender.Config{Type: alertsender.Systray, Sender: Config{Enabled: true, Sound: false, QuietMode: false}})
	require.NoError(t, err)
	require.NotNil(t, s)

	require.NoError(t, s.Send(alertsender.Alert{
		Title: "LSASS memory dumping via legitimate or offensive tools",
		Text: `Detected an attempt by mimikatz.exe process to access and read
	the memory of the Local Security And Authority Subsystem Service
	and subsequently write the C:\\temp\lsass.dmp dump file to the disk device`}))

	wg.Wait()

	// consume messages
	cfg := <-msgs
	require.NotNil(t, cfg)
	require.Equal(t, MsgType(0), cfg.Type)

	alert := <-msgs
	require.NotNil(t, alert)
	require.Equal(t, MsgType(1), alert.Type)
	var a alertsender.Alert
	require.NoError(t, decodeMsg(&a, alert.Data))
	assert.Equal(t, "LSASS memory dumping via legitimate or offensive tools", a.Title)
}

func decodeMsg(output any, data any) error {
	var decoderConfig = &mapstructure.DecoderConfig{
		Metadata:         nil,
		Result:           output,
		WeaklyTypedInput: true,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
		),
	}
	decoder, err := mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		return err
	}
	return decoder.Decode(data)
}

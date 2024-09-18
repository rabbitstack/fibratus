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

package amqp

import (
	"encoding/json"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"golang.org/x/sys/windows"
	"testing"
	"time"

	"github.com/phayes/freeport"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/config"
	broker "github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/server"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/streadway/amqp"
	"github.com/stretchr/testify/require"
)

func TestPublishAmqpOutput(t *testing.T) {
	// deadlock occurs somewhere in the garagemq code
	// when tests are executed in the CI platform.
	// Reenable test once we fix the issue
	t.SkipNow()
	port, err := freeport.GetFreePort()
	require.NoError(t, err)
	amqpBroker := broker.NewServer("127.0.0.1", fmt.Sprintf("%d", port), "amqp-rabbit", config.Default())

	done := make(chan struct{})

	go func() {
		amqpBroker.Start()
	}()
	defer amqpBroker.Stop()

	q := rabbitmq{client: newClient(Config{
		URL:          amqpURL(port),
		Exchange:     "fibratus",
		ExchangeType: "topic",
		RoutingKey:   "fibratus",
	})}

	time.AfterFunc(time.Second*4, func() { done <- struct{}{} })

	require.NoError(t, q.Connect())
	defer q.Close()

	err = consumeKevents(t, amqpURL(port), done)
	require.NoError(t, err)

	err = q.Publish(getBatch())
	require.NoError(t, err)

	<-done
}

func TestHealthcheck(t *testing.T) {
	// deadlock occurs somewhere in the garagemq code
	// when tests are executed in the CI platform.
	// Reenable test once we fix the issue
	t.SkipNow()
	port, err := freeport.GetFreePort()
	require.NoError(t, err)
	amqpBroker := broker.NewServer("127.0.0.1", fmt.Sprintf("%d", port), "amqp-rabbit", config.Default())

	go func() {
		amqpBroker.Start()
	}()

	q := rabbitmq{client: newClient(Config{
		URL:          amqpURL(port),
		Exchange:     "fibratus",
		ExchangeType: "topic",
		RoutingKey:   "fibratus",
		Timeout:      time.Second,
	})}
	require.NoError(t, q.Connect())
	defer q.Close()

	time.Sleep(time.Millisecond * 400)

	amqpBroker.Stop()

	err = q.Publish(getBatch())
	require.Error(t, err)

	time.Sleep(time.Millisecond * 100)

	go func() {
		amqpBroker.Start()
	}()

	time.Sleep(time.Millisecond * 2000)
	require.NoError(t, q.client.declareExchange())
	err = q.Publish(getBatch())
	require.NoError(t, err)
}

//nolint:unused
func consumeKevents(t *testing.T, amqpURI string, done chan struct{}) error {
	conn, err := amqp.Dial(amqpURI)
	if err != nil {
		return err
	}

	channel, err := conn.Channel()
	if err != nil {
		return err
	}
	queue, err := channel.QueueDeclare(
		"fibratus", // name of the queue
		true,       // durable
		false,      // delete when unused
		false,      // exclusive
		false,      // noWait
		nil,        // arguments
	)
	if err != nil {
		return err
	}
	if err = channel.QueueBind(
		queue.Name, // name of the queue
		"fibratus", // bindingKey
		"fibratus", // sourceExchange
		false,      // noWait
		nil,        // arguments
	); err != nil {
		return err
	}
	deliveries, err := channel.Consume(
		queue.Name,         // name
		"kevents-consumer", // consumerTag,
		false,              // noAck
		false,              // exclusive
		false,              // noLocal
		false,              // noWait
		nil,                // arguments
	)
	require.NoError(t, err)

	go func() {
		for d := range deliveries {
			body := d.Body
			if len(body) == 0 {
				done <- struct{}{}
				t.Error("got empty AMQP message")
			}
			var kevents []*kevent.Kevent
			err := json.Unmarshal(body, &kevents)
			if err != nil {
				done <- struct{}{}
				t.Error(err)
			}
			if len(kevents) != 3 {
				done <- struct{}{}
				t.Errorf("expected 3 events in body but got %d", len(kevents))
			}
			err = d.Ack(false)
			if err != nil {
				t.Error(err)
			}
			done <- struct{}{}
		}
	}()

	return nil
}

//nolint:unused
func amqpURL(port int) string {
	return fmt.Sprintf("amqp://localhost:%d", port)
}

//nolint:unused
func getBatch() *kevent.Batch {
	kevt := &kevent.Kevent{
		Type:        ktypes.CreateFile,
		Tid:         2484,
		PID:         859,
		CPU:         1,
		Seq:         2,
		Name:        "CreateFile",
		Timestamp:   time.Now(),
		Category:    ktypes.File,
		Host:        "archrabbit",
		Description: "Creates or opens a new file, directory, I/O device, pipe, console",
		Kparams: kevent.Kparams{
			kparams.FileObject:    {Name: kparams.FileObject, Type: kparams.Uint64, Value: uint64(12456738026482168384)},
			kparams.FileName:      {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll"},
			kparams.FileType:      {Name: kparams.FileType, Type: kparams.AnsiString, Value: "file"},
			kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.AnsiString, Value: "open"},
			kparams.BasePrio:      {Name: kparams.BasePrio, Type: kparams.Int8, Value: int8(2)},
			kparams.PagePrio:      {Name: kparams.PagePrio, Type: kparams.Uint8, Value: uint8(2)},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "baarz"},
		PS: &pstypes.PS{
			PID:       2436,
			Ppid:      6304,
			Name:      "firefox.exe",
			Exe:       `C:\Program Files\Mozilla Firefox\firefox.exe`,
			Cmdline:   `C:\Program Files\Mozilla Firefox\firefox.exe -contentproc --channel="6304.3.1055809391\1014207667" -childID 1 -isForBrowser -prefsHandle 2584 -prefMapHandle 2580 -prefsLen 70 -prefMapSize 216993 -parentBuildID 20200107212822 -greomni "C:\Program Files\Mozilla Firefox\omni.ja" -appomni "C:\Program Files\Mozilla Firefox\browser\omni.ja" -appdir "C:\Program Files\Mozilla Firefox\browser" - 6304 "\\.\pipe\gecko-crash-server-pipe.6304" 2596 tab`,
			Cwd:       `C:\Program Files\Mozilla Firefox\`,
			SID:       "S-1-1-18",
			Args:      []string{"-contentproc", `--channel=6304.3.1055809391\1014207667`, "-childID", "1", "-isForBrowser", "-prefsHandle", "2584", "-prefMapHandle", "2580", "-prefsLen", "70", "-prefMapSize", "216993", "-parentBuildID"},
			SessionID: 4,
			Envs:      map[string]string{"ProgramData": "C:\\ProgramData", "COMPUTRENAME": "archrabbit"},
			Threads: map[uint32]pstypes.Thread{
				3453: {Tid: 3453, StartAddress: va.Address(140729524944768), IOPrio: 2, PagePrio: 5, KstackBase: va.Address(18446677035730165760), KstackLimit: va.Address(18446677035730137088), UstackLimit: va.Address(86376448), UstackBase: va.Address(86372352)},
				3455: {Tid: 3455, StartAddress: va.Address(140729524944768), IOPrio: 3, PagePrio: 5, KstackBase: va.Address(18446677035730165760), KstackLimit: va.Address(18446677035730137088), UstackLimit: va.Address(86376448), UstackBase: va.Address(86372352)},
			},
			Handles: []htypes.Handle{
				{Num: windows.Handle(0xffffd105e9baaf70),
					Name:   `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{b677c565-6ca5-45d3-b618-736b4e09b036}`,
					Type:   "Key",
					Object: 777488883434455544,
					Pid:    uint32(1023),
				},
				{
					Num:  windows.Handle(0xffffd105e9adaf70),
					Name: `\RPC Control\OLEA61B27E13E028C4EA6C286932E80`,
					Type: "ALPC Port",
					Pid:  uint32(1023),
					MD: &htypes.AlpcPortInfo{
						Seqno:   1,
						Context: 0x0,
						Flags:   0x0,
					},
					Object: 457488883434455544,
				},
				{
					Num:  windows.Handle(0xeaffd105e9adaf30),
					Name: `C:\Users\bunny`,
					Type: "File",
					Pid:  uint32(1023),
					MD: &htypes.FileInfo{
						IsDirectory: true,
					},
					Object: 357488883434455544,
				},
			},
		},
	}

	kevt1 := &kevent.Kevent{
		Type:        ktypes.CreateFile,
		Tid:         2484,
		PID:         459,
		CPU:         1,
		Seq:         2,
		Name:        "CreateFile",
		Timestamp:   time.Now(),
		Category:    ktypes.File,
		Host:        "archrabbit",
		Description: "Creates or opens a new file, directory, I/O device, pipe, console",
		Kparams: kevent.Kparams{
			kparams.FileObject:    {Name: kparams.FileObject, Type: kparams.Uint64, Value: uint64(12456738026482168384)},
			kparams.FileName:      {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll"},
			kparams.FileType:      {Name: kparams.FileType, Type: kparams.AnsiString, Value: "file"},
			kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.AnsiString, Value: "open"},
			kparams.BasePrio:      {Name: kparams.BasePrio, Type: kparams.Int8, Value: int8(2)},
			kparams.PagePrio:      {Name: kparams.PagePrio, Type: kparams.Uint8, Value: uint8(2)},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "baarz"},
		PS: &pstypes.PS{
			PID:       2436,
			Ppid:      6304,
			Name:      "firefox.exe",
			Exe:       `C:\Program Files\Mozilla Firefox\firefox.exe`,
			Cmdline:   `C:\Program Files\Mozilla Firefox\firefox.exe -contentproc --channel="6304.3.1055809391\1014207667" -childID 1 -isForBrowser -prefsHandle 2584 -prefMapHandle 2580 -prefsLen 70 -prefMapSize 216993 -parentBuildID 20200107212822 -greomni "C:\Program Files\Mozilla Firefox\omni.ja" -appomni "C:\Program Files\Mozilla Firefox\browser\omni.ja" -appdir "C:\Program Files\Mozilla Firefox\browser" - 6304 "\\.\pipe\gecko-crash-server-pipe.6304" 2596 tab`,
			Cwd:       `C:\Program Files\Mozilla Firefox\`,
			SID:       "S-1-1-18",
			Args:      []string{"-contentproc", `--channel=6304.3.1055809391\1014207667`, "-childID", "1", "-isForBrowser", "-prefsHandle", "2584", "-prefMapHandle", "2580", "-prefsLen", "70", "-prefMapSize", "216993", "-parentBuildID"},
			SessionID: 4,
			Envs:      map[string]string{"ProgramData": "C:\\ProgramData", "COMPUTRENAME": "archrabbit"},
			Threads: map[uint32]pstypes.Thread{
				3453: {Tid: 3453, StartAddress: va.Address(140729524944768), IOPrio: 2, PagePrio: 5, KstackBase: va.Address(18446677035730165760), KstackLimit: va.Address(18446677035730137088), UstackLimit: va.Address(86376448), UstackBase: va.Address(86372352)},
				3455: {Tid: 3455, StartAddress: va.Address(140729524944768), IOPrio: 3, PagePrio: 5, KstackBase: va.Address(18446677035730165760), KstackLimit: va.Address(18446677035730137088), UstackLimit: va.Address(86376448), UstackBase: va.Address(86372352)},
			},
			Handles: []htypes.Handle{
				{Num: windows.Handle(0xffffd105e9baaf70),
					Name:   `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{b677c565-6ca5-45d3-b618-736b4e09b036}`,
					Type:   "Key",
					Object: 777488883434455544,
					Pid:    uint32(1023),
				},
				{
					Num:  windows.Handle(0xffffd105e9adaf70),
					Name: `\RPC Control\OLEA61B27E13E028C4EA6C286932E80`,
					Type: "ALPC Port",
					Pid:  uint32(1023),
					MD: &htypes.AlpcPortInfo{
						Seqno:   1,
						Context: 0x0,
						Flags:   0x0,
					},
					Object: 457488883434455544,
				},
				{
					Num:  windows.Handle(0xeaffd105e9adaf30),
					Name: `C:\Users\bunny`,
					Type: "File",
					Pid:  uint32(1023),
					MD: &htypes.FileInfo{
						IsDirectory: true,
					},
					Object: 357488883434455544,
				},
			},
		},
	}

	kevt2 := &kevent.Kevent{
		Type:        ktypes.CreateFile,
		Tid:         2484,
		PID:         829,
		CPU:         1,
		Seq:         2,
		Name:        "CreateFile",
		Timestamp:   time.Now(),
		Category:    ktypes.File,
		Host:        "archrabbit",
		Description: "Creates or opens a new file, directory, I/O device, pipe, console",
		Kparams: kevent.Kparams{
			kparams.FileObject:    {Name: kparams.FileObject, Type: kparams.Uint64, Value: uint64(12456738026482168384)},
			kparams.FileName:      {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll"},
			kparams.FileType:      {Name: kparams.FileType, Type: kparams.AnsiString, Value: "file"},
			kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.AnsiString, Value: "open"},
			kparams.BasePrio:      {Name: kparams.BasePrio, Type: kparams.Int8, Value: int8(2)},
			kparams.PagePrio:      {Name: kparams.PagePrio, Type: kparams.Uint8, Value: uint8(2)},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "baarz"},
		PS: &pstypes.PS{
			PID:       829,
			Ppid:      6304,
			Name:      "firefox.exe",
			Exe:       `C:\Program Files\Mozilla Firefox\firefox.exe`,
			Cmdline:   `C:\Program Files\Mozilla Firefox\firefox.exe -contentproc --channel="6304.3.1055809391\1014207667" -childID 1 -isForBrowser -prefsHandle 2584 -prefMapHandle 2580 -prefsLen 70 -prefMapSize 216993 -parentBuildID 20200107212822 -greomni "C:\Program Files\Mozilla Firefox\omni.ja" -appomni "C:\Program Files\Mozilla Firefox\browser\omni.ja" -appdir "C:\Program Files\Mozilla Firefox\browser" - 6304 "\\.\pipe\gecko-crash-server-pipe.6304" 2596 tab`,
			Cwd:       `C:\Program Files\Mozilla Firefox\`,
			SID:       "S-1-1-18",
			Args:      []string{"-contentproc", `--channel=6304.3.1055809391\1014207667`, "-childID", "1", "-isForBrowser", "-prefsHandle", "2584", "-prefMapHandle", "2580", "-prefsLen", "70", "-prefMapSize", "216993", "-parentBuildID"},
			SessionID: 4,
			Envs:      map[string]string{"ProgramData": "C:\\ProgramData", "COMPUTRENAME": "archrabbit"},
			Threads: map[uint32]pstypes.Thread{
				3453: {Tid: 3453, StartAddress: va.Address(140729524944768), IOPrio: 2, PagePrio: 5, KstackBase: va.Address(18446677035730165760), KstackLimit: va.Address(18446677035730137088), UstackLimit: va.Address(86376448), UstackBase: va.Address(86372352)},
				3455: {Tid: 3455, StartAddress: va.Address(140729524944768), IOPrio: 3, PagePrio: 5, KstackBase: va.Address(18446677035730165760), KstackLimit: va.Address(18446677035730137088), UstackLimit: va.Address(86376448), UstackBase: va.Address(86372352)},
			},
			Handles: []htypes.Handle{
				{Num: windows.Handle(0xffffd105e9baaf70),
					Name:   `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{b677c565-6ca5-45d3-b618-736b4e09b036}`,
					Type:   "Key",
					Object: 777488883434455544,
					Pid:    uint32(1023),
				},
				{
					Num:  windows.Handle(0xffffd105e9adaf70),
					Name: `\RPC Control\OLEA61B27E13E028C4EA6C286932E80`,
					Type: "ALPC Port",
					Pid:  uint32(1023),
					MD: &htypes.AlpcPortInfo{
						Seqno:   1,
						Context: 0x0,
						Flags:   0x0,
					},
					Object: 457488883434455544,
				},
				{
					Num:  windows.Handle(0xeaffd105e9adaf30),
					Name: `C:\Users\bunny`,
					Type: "File",
					Pid:  uint32(1023),
					MD: &htypes.FileInfo{
						IsDirectory: true,
					},
					Object: 357488883434455544,
				},
			},
		},
	}

	return kevent.NewBatch(kevt, kevt1, kevt2)
}

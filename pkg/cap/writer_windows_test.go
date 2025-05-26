//go:build cap
// +build cap

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

package cap

import (
	"github.com/rabbitstack/fibratus/internal/etw"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/handle"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/ps"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"testing"
	"time"
)

func TestWrite(t *testing.T) {
	psnap := new(ps.SnapshotterMock)
	hsnap := new(handle.SnapshotterMock)
	log.SetLevel(log.DebugLevel)

	procs := []*pstypes.PS{
		{PID: 8390, Ppid: 1096, Name: "spotify.exe", Exe: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe`, Cmdline: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`, Cwd: `C:\Users\admin\AppData\Roaming\Spotify`, SID: "admin\\SYSTEM"},
		{PID: 2436, Ppid: 6304, Name: "firefox.exe", Exe: `C:\Program Files\Mozilla Firefox\firefox.exe`, Cmdline: `C:\Program Files\Mozilla Firefox\firefox.exe" -contentproc --channel="6304.3.1055809391\1014207667" -childID 1 -isForBrowser -prefsHandle 2584 -prefMapHandle 2580 -prefsLen 70 -prefMapSize 216993 -parentBuildID 20200107212822 -greomni "C:\Program Files\Mozilla Firefox\omni.ja" -appomni "C:\Program Files\Mozilla Firefox\browser\omni.ja" -appdir "C:\Program Files\Mozilla Firefox\browser" - 6304 "\\.\pipe\gecko-crash-server-pipe.6304" 2596 tab`, Cwd: `C:\Program Files\Mozilla Firefox\`, SID: "archrabbit\\SYSTEM"},
	}

	handles := []htypes.Handle{
		{Pid: 8390, Name: "C:\\Windows", Type: "File"},
		{Pid: 8390, Name: "C:\\Windows\\System32", Type: "File"},
	}

	psnap.On("GetSnapshot").Return(procs)
	psnap.On("Size").Return(len(procs))

	hsnap.On("GetSnapshot").Return(handles)

	w, err := NewWriter("_fixtures/cap.cap", psnap, hsnap)
	require.NoError(t, err)
	require.NotNil(t, w)

	evtsc := make(chan *event.Event, 100)
	errs := make(chan error, 10)

	for i := 0; i < 100; i++ {
		evt := &event.Event{
			Type:        event.CreateFile,
			Tid:         2484,
			PID:         859,
			CPU:         uint8(i / 2),
			Seq:         uint64(i + 1),
			Name:        "CreateFile",
			Timestamp:   time.Now(),
			Category:    event.File,
			Host:        "archrabbit",
			Description: "Creates or opens a new file, directory, I/O device, pipe, console",
			Params: event.Params{
				params.FileObject:    {Name: params.FileObject, Type: params.Uint64, Value: uint64(12456738026482168384)},
				params.FilePath:      {Name: params.FilePath, Type: params.UnicodeString, Value: "\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll"},
				params.FileType:      {Name: params.FileType, Type: params.AnsiString, Value: "file"},
				params.FileOperation: {Name: params.FileOperation, Type: params.AnsiString, Value: "open"},
			},
			Metadata: map[event.MetadataKey]any{"foo": "bar", "fooz": "barz"},
			PS: &pstypes.PS{
				PID:       2436,
				Ppid:      6304,
				Name:      "firefox.exe",
				Exe:       `C:\Program Files\Mozilla Firefox\firefox.exe`,
				Cmdline:   `C:\Program Files\Mozilla Firefox\firefox.exe -contentproc --channel="6304.3.1055809391\1014207667" -childID 1 -isForBrowser -prefsHandle 2584 -prefMapHandle 2580 -prefsLen 70 -prefMapSize 216993 -parentBuildID 20200107212822 -greomni "C:\Program Files\Mozilla Firefox\omni.ja" -appomni "C:\Program Files\Mozilla Firefox\browser\omni.ja" -appdir "C:\Program Files\Mozilla Firefox\browser" - 6304 "\\.\pipe\gecko-crash-server-pipe.6304" 2596 tab`,
				Cwd:       `C:\Program Files\Mozilla Firefox\`,
				SID:       "S-1-15-2",
				Args:      []string{"-contentproc", `--channel="6304.3.1055809391\1014207667`, "-childID", "1", "-isForBrowser", "-prefsHandle", "2584", "-prefMapHandle", "2580", "-prefsLen", "70", "-prefMapSize", "216993", "-parentBuildID"},
				SessionID: 4,
				Envs:      map[string]string{"ProgramData": "C:\\ProgramData", "COMPUTRENAME": "archrabbit"},
				Handles: []htypes.Handle{
					{
						Num:    windows.Handle(0xffffd105e9baaf70),
						Name:   `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{b677c565-6ca5-45d3-b618-736b4e09b036}`,
						Type:   "Key",
						Object: 777488883434455544,
						Pid:    uint32(1023),
					},
					{
						Num:    windows.Handle(0xe1ffd105e9baaf70),
						Type:   "Event",
						Object: 777488883434455544,
						Pid:    uint32(1023),
					},
					{
						Type: "Event",
					},
					{
						Num:  windows.Handle(0xe1ecd105e9baaf70),
						Type: "Event",
						Pid:  uint32(1023),
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
		if i%2 == 0 {
			evt.PS.Handles = append(evt.PS.Handles, htypes.Handle{})
		}
		evtsc <- evt
	}

	werrs := w.Write(evtsc, errs)
	quit := make(chan struct{}, 1)
	time.AfterFunc(time.Second*5, func() {
		quit <- struct{}{}
	})
	select {
	case err := <-werrs:
		t.Fatal(err)
	case <-quit:
		w.Close()
		require.True(t, w.(*writer).stats.evtsWritten > 0)
		return
	}
}

func TestLiveCapture(t *testing.T) {
	t.SkipNow()
	cfg := &config.Config{
		EventSource: config.EventSourceConfig{
			EnableFileIOEvents:   true,
			EnableImageEvents:    true,
			EnableRegistryEvents: true,
			EnableNetEvents:      true,
			EnableThreadEvents:   true,
			EnableHandleEvents:   true,
		},
		CapFile:            "../../test.cap",
		Filters:            &config.Filters{},
		InitHandleSnapshot: true,
	}
	wait := make(chan struct{}, 1)
	cb := func(total uint64, withName uint64) {
		wait <- struct{}{}
	}
	hsnap := handle.NewSnapshotter(cfg, cb)
	psnap := ps.NewSnapshotter(hsnap, cfg)

	<-wait

	evs := etw.NewEventSource(psnap, hsnap, cfg, nil)
	err := evs.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// bootstrap cap writer with inbound event channel
	writer, err := NewWriter(cfg.CapFile, psnap, hsnap)
	if err != nil {
		t.Fatal(err)
	}
	writer.Write(evs.Events(), evs.Errors())

	// capture for a minute
	<-time.After(time.Minute)

	writer.Close()

	_ = evs.Close()
}

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

package eventlog

import (
	"errors"
	"text/template"

	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"

	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/outputs"
)

const (
	// source under which eventlog events are reported
	source = "Fibratus"
	// levels designates the supported eventlog levels
	levels = uint32(Info | Warn | Erro)
	// msgFile specifies the location of the eventlog message DLL
	msgFile = "%ProgramFiles%\\Fibratus\\fibratus.dll"
	// unknownEventID represents the unknown event identifier
	unknownEventID = 0
)

// ErrUnknownEventID represents the error for signaling unknown event identifiers. This error
// is raised when we can't get a valid mapping for the existing kernel event type.
var ErrUnknownEventID = errors.New("unknown event id found")

type evtlog struct {
	evtlog *Eventlog // eventlog writer
	config Config
	tmpl   *template.Template
}

func init() {
	outputs.Register(outputs.Eventlog, initEventlog)
}

func initEventlog(config outputs.Config) (outputs.OutputGroup, error) {
	cfg, ok := config.Output.(Config)
	if !ok {
		return outputs.Fail(outputs.ErrInvalidConfig(outputs.Eventlog, config.Output))
	}
	err := Install(source, msgFile, false, levels)
	if err != nil {
		// ignore error if the key already exists
		if !errors.Is(err, ErrKeyExists) {
			return outputs.Fail(err)
		}
	}
	evtlog := &evtlog{
		config: cfg,
	}
	evtlog.tmpl, err = cfg.parseTemplate()
	if err != nil {
		return outputs.Fail(err)
	}
	return outputs.Success(evtlog), nil
}

func (e *evtlog) Connect() error {
	var (
		evl *Eventlog
		err error
	)
	if e.config.RemoteHost != "" {
		evl, err = OpenRemote(e.config.RemoteHost, source)
	} else {
		evl, err = Open(source)
	}
	if err != nil {
		return err
	}
	e.evtlog = evl
	return nil
}

func (e *evtlog) Close() error {
	if e.evtlog != nil {
		return e.evtlog.Close()
	}
	return nil
}

func (e *evtlog) Publish(batch *kevent.Batch) error {
	defer batch.Release()

	for _, kevt := range batch.Events {
		if err := e.publish(kevt); err != nil {
			return err
		}
	}

	return nil
}

func (e *evtlog) publish(kevt *kevent.Kevent) error {
	buf, err := e.renderTemplate(kevt)
	if err != nil {
		return err
	}
	eventID := ktypeToEventID(kevt)
	if eventID == unknownEventID {
		return ErrUnknownEventID
	}
	err = e.log(eventID, categoryID(kevt), buf)
	if err != nil {
		return err
	}
	return nil
}

func (e *evtlog) log(eventID uint32, categoryID uint16, buf []byte) error {
	switch levelFromString(e.config.Level) {
	case Info:
		return e.evtlog.Info(eventID, categoryID, buf)
	case Warn:
		return e.evtlog.Warning(eventID, categoryID, buf)
	case Erro:
		return e.evtlog.Error(eventID, categoryID, buf)
	default:
		panic("unknown eventlog level")
	}
}

// kcatToCategoryID maps category name to eventlog identifier.
func categoryID(kevt *kevent.Kevent) uint16 {
	switch kevt.Category {
	case ktypes.Registry:
		return 1
	case ktypes.File:
		return 2
	case ktypes.Net:
		return 3
	case ktypes.Process:
		return 4
	case ktypes.Thread:
		return 5
	case ktypes.Image:
		return 6
	case ktypes.Handle:
		return 7
	case ktypes.Other:
		return 8
	default:
		return 0
	}
}

// ktypeToEventID returns the event ID from the event type.
func ktypeToEventID(kevt *kevent.Kevent) uint32 {
	switch kevt.Type {
	case ktypes.CreateProcess:
		return 15
	case ktypes.TerminateProcess:
		return 16
	case ktypes.OpenProcess:
		return 17
	case ktypes.LoadImage:
		return 18
	case ktypes.Connect:
		return 19
	case ktypes.CreateFile:
		return 20
	case ktypes.RegDeleteKey:
		return 21
	case ktypes.RegDeleteValue:
		return 22
	case ktypes.RegCreateKey:
		return 23
	case ktypes.RegSetValue:
		return 24
	case ktypes.CreateHandle:
		return 25
	case ktypes.DeleteFile:
		return 26
	case ktypes.CreateThread:
		return 27
	case ktypes.TerminateThread:
		return 28
	case ktypes.OpenThread:
		return 29
	case ktypes.UnloadImage:
		return 30
	case ktypes.WriteFile:
		return 31
	case ktypes.ReadFile:
		return 32
	case ktypes.RenameFile:
		return 33
	case ktypes.CloseFile:
		return 34
	case ktypes.SetFileInformation:
		return 35
	case ktypes.EnumDirectory:
		return 36
	case ktypes.RegOpenKey:
		return 37
	case ktypes.RegQueryKey:
		return 38
	case ktypes.RegQueryValue:
		return 39
	case ktypes.Accept:
		return 40
	case ktypes.Send:
		return 41
	case ktypes.Recv:
		return 42
	case ktypes.Disconnect:
		return 43
	case ktypes.Reconnect:
		return 44
	case ktypes.Retransmit:
		return 45
	case ktypes.CloseHandle:
		return 46
	}
	return unknownEventID
}

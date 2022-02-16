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
	"encoding/xml"
	"errors"
	"fmt"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"

	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/outputs"
	"golang.org/x/sys/windows/svc/eventlog"
)

const (
	// source under which eventlog events are reported
	source = "Fibratus"
	// levels designates the supported eventlog levels
	levels = uint32(Info | Warn | Erro)
)

var (
	// ErrUnknownLogLevel the error type that signify an unknown log level
	ErrUnknownLogLevel           = errors.New("unknown log level")
	keyAlreadyExistsErrorMessage = fmt.Sprintf("%s registry key already exists", source)
)

type evtlog struct {
	evtlog *Eventlog // eventlog writer
	config Config
}

func init() {
	outputs.Register(outputs.Eventlog, initEventlog)
}

func initEventlog(config outputs.Config) (outputs.OutputGroup, error) {
	cfg, ok := config.Output.(Config)
	if !ok {
		return outputs.Fail(outputs.ErrInvalidConfig(outputs.Eventlog, config.Output))
	}
	err := eventlog.Install(source, `C:\Fibratus\fibratus\pkg\outputs\eventlog\mc\fibratus.mc.dll`, false, levels)
	if err != nil {
		// ignore error if the key already exists
		if !strings.HasSuffix(err.Error(), keyAlreadyExistsErrorMessage) {
			return outputs.Fail(err)
		}
	}
	evtlog := &evtlog{
		config: cfg,
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
	var (
		eventID    = ktypeToEventID(kevt)
		categoryID = categoryToID(kevt)
	)
	switch e.config.Serializer {
	case outputs.XML:
		buf, err := xml.MarshalIndent(kevt, "", " ")
		if err != nil {
			return err
		}
		err = e.writeEvtlog(eventID, categoryID, buf)
		if err != nil {
			return err
		}

	case outputs.Text:
		buf, err := kevt.MarshalText()
		if err != nil {
			return err
		}
		err = e.writeEvtlog(eventID, categoryID, buf)
		if err != nil {
			return err
		}
	}
	return nil
}

func (e *evtlog) writeEvtlog(eventID uint32, categoryID uint16, buf []byte) error {
	switch levelFromString(e.config.Level) {
	case Info:
		return e.evtlog.Info(eventID, categoryID, buf)
	case Warn:
		return e.evtlog.Warning(eventID, categoryID, buf)
	case Erro:
		return e.evtlog.Error(eventID, categoryID, buf)
	default:
		return ErrUnknownLogLevel
	}
}

// categoryToID maps category name to eventlog identifier.
func categoryToID(kevt *kevent.Kevent) uint16 {
	switch kevt.Category {
	case ktypes.Registry:
		return 1
	case ktypes.File:
		return 2
	default:
		return 8
	}
}

// ktypeToEventID returns the event ID from the event type.
func ktypeToEventID(kevt *kevent.Kevent) uint32 {
	switch kevt.Type {
	case ktypes.CreateProcess:
		return 10
	case ktypes.TerminateProcess:
		return 11
	case ktypes.OpenProcess:
		return 12
	case ktypes.LoadImage:
		return 13
	case ktypes.Connect:
		return 14
	case ktypes.CreateFile:
		return 15
	case ktypes.RegDeleteKey:
		return 16
	case ktypes.RegDeleteValue:
		return 17
	case ktypes.RegCreateKey:
		return 18
	case ktypes.RegSetValue:
		return 19
	case ktypes.CreateHandle:
		return 20
	case ktypes.DeleteFile:
		return 21
	case ktypes.CreateThread:
		return 22
	case ktypes.TerminateThread:
		return 23
	case ktypes.OpenThread:
		return 24
	case ktypes.UnloadImage:
		return 25
	case ktypes.WriteFile:
		return 26
	case ktypes.ReadFile:
		return 27
	case ktypes.RenameFile:
		return 28
	case ktypes.CloseFile:
		return 29
	case ktypes.SetFileInformation:
		return 31
	case ktypes.EnumDirectory:
		return 32
	case ktypes.RegOpenKey:
		return 33
	case ktypes.RegQueryKey:
		return 34
	case ktypes.RegQueryValue:
		return 35
	case ktypes.Accept:
		return 36
	case ktypes.Send:
		return 37
	case ktypes.Recv:
		return 38
	case ktypes.Disconnect:
		return 39
	case ktypes.Reconnect:
		return 40
	case ktypes.Retransmit:
		return 41
	case ktypes.CloseHandle:
		return 44
	}
	return 255
}

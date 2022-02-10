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

	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"

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
	err := eventlog.InstallAsEventCreate(source, levels)
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
		l   *Eventlog
		err error
	)
	if e.config.RemoteHost != "" {
		l, err = OpenRemote(e.config.RemoteHost, source)
	} else {
		l, err = Open(source)
	}
	if err != nil {
		return err
	}
	e.evtlog = l
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
	switch e.config.Serializer {
	case outputs.XML:
		buf, err := xml.MarshalIndent(kevt, "", " ")
		if err != nil {
			return err
		}
		err = e.writeEvtlog(ktypeToEventID(kevt), buf)
		if err != nil {
			return err
		}

	case outputs.Text:
		buf, err := kevt.MarshalText()
		if err != nil {
			return err
		}
		err = e.writeEvtlog(ktypeToEventID(kevt), buf)
		if err != nil {
			return err
		}
	}
	return nil
}

func (e *evtlog) writeEvtlog(eventID uint32, buf []byte) error {
	switch levelFromString(e.config.Level) {
	case Info:
		return e.evtlog.Info(eventID, buf)
	case Warn:
		return e.evtlog.Warning(eventID, buf)
	case Erro:
		return e.evtlog.Error(eventID, buf)
	default:
		return ErrUnknownLogLevel
	}
}

// ktypeToEventID is the best effort to keep the event enumeration parity
// with sysmon. For any event that can't directly be mapped to the corresponding
// sysmon event, we establish our own event identifiers.
func ktypeToEventID(kevt *kevent.Kevent) uint32 {
	switch kevt.Type {
	case ktypes.CreateProcess:
		return 1
	case ktypes.TerminateProcess:
		return 2
	case ktypes.OpenProcess:
		return 10
	case ktypes.LoadImage:
		return 7
	case ktypes.Connect:
		return 3
	case ktypes.CreateFile:
		return 11
	case ktypes.RegDeleteKey, ktypes.RegDeleteValue, ktypes.RegCreateKey:
		return 12
	case ktypes.RegSetValue:
		return 13
	case ktypes.CreateHandle:
		handleType, _ := kevt.Kparams.GetString(kparams.HandleObjectTypeName)
		handleName, _ := kevt.Kparams.GetString(kparams.HandleObjectName)
		if handleType == "File" && strings.HasPrefix(handleName, "\\Device\\NamedPipe\\") {
			// sysmon pipe created event
			return 17
		}
		return 119
	case ktypes.DeleteFile:
		return 26
	case ktypes.CreateThread: // custom event identifiers
		return 100
	case ktypes.TerminateThread:
		return 101
	case ktypes.OpenThread:
		return 102
	case ktypes.UnloadImage:
		return 103
	case ktypes.WriteFile:
		return 104
	case ktypes.ReadFile:
		return 105
	case ktypes.RenameFile:
		return 106
	case ktypes.CloseFile:
		return 107
	case ktypes.SetFileInformation:
		return 108
	case ktypes.EnumDirectory:
		return 109
	case ktypes.RegOpenKey:
		return 110
	case ktypes.RegQueryKey:
		return 111
	case ktypes.RegQueryValue:
		return 112
	case ktypes.Accept:
		return 113
	case ktypes.Send:
		return 114
	case ktypes.Recv:
		return 115
	case ktypes.Disconnect:
		return 116
	case ktypes.Reconnect:
		return 117
	case ktypes.Retransmit:
		return 118
	case ktypes.CloseHandle:
		return 120
	}
	return 255
}

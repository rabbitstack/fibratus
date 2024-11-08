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

//go:generate go run github.com/rabbitstack/fibratus/pkg/outputs/eventlog/mc

package eventlog

import (
	"errors"
	"github.com/rabbitstack/fibratus/pkg/util/eventlog"
	"golang.org/x/sys/windows"
	"text/template"

	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"

	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/outputs"
)

const (
	// categoryOffset specifies the start of the event id number space
	categoryOffset = 25
)

// ErrUnknownEventID represents the error for signaling unknown event identifiers. This error
// is raised when we can't get a valid mapping for the existing kernel event type.
var ErrUnknownEventID = errors.New("unknown event id found")

type evtlog struct {
	evtlog *Eventlog // eventlog writer
	config Config
	tmpl   *template.Template
	events []ktypes.KeventInfo
	cats   []string
}

func init() {
	outputs.Register(outputs.Eventlog, initEventlog)
}

func initEventlog(config outputs.Config) (outputs.OutputGroup, error) {
	cfg, ok := config.Output.(Config)
	if !ok {
		return outputs.Fail(outputs.ErrInvalidConfig(outputs.Eventlog, config.Output))
	}
	err := eventlog.Install(eventlog.Levels)
	if err != nil {
		// ignore error if the key already exists
		if !errors.Is(err, eventlog.ErrKeyExists) {
			return outputs.Fail(err)
		}
	}
	evtlog := &evtlog{
		config: cfg,
		events: ktypes.GetKtypesMetaIndexed(),
		cats:   ktypes.Categories(),
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
		evl, err = OpenRemote(e.config.RemoteHost, eventlog.Source)
	} else {
		evl, err = Open(eventlog.Source)
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
	for _, kevt := range batch.Events {
		if err := e.publish(kevt); err != nil {
			return err
		}
	}
	return nil
}

func (e *evtlog) publish(kevt *kevent.Kevent) error {
	buf, err := kevt.RenderCustomTemplate(e.tmpl)
	if err != nil {
		return err
	}
	categoryID := e.categoryID(kevt)
	eventID := eventlog.EventID(windows.EVENTLOG_INFORMATION_TYPE, uint16(e.eventCode(kevt)))
	if eventID == 0 {
		return ErrUnknownEventID
	}
	err = e.evtlog.Info(eventID, categoryID, buf)
	if err != nil {
		return err
	}
	return nil
}

// categoryID maps category name to eventlog identifier.
func (e *evtlog) categoryID(kevt *kevent.Kevent) uint16 {
	for i, cat := range e.cats {
		if cat == string(kevt.Category) {
			return uint16(i + 1)
		}
	}
	return 0
}

// eventCode returns the event ID from the event type.
func (e *evtlog) eventCode(kevt *kevent.Kevent) uint32 {
	for i, evt := range e.events {
		if evt.Name == kevt.Name {
			return uint32(i + categoryOffset)
		}
	}
	return 0
}

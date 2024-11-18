/*
 * Copyright 2012 The Go Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 *
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
	"bytes"
	"errors"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/util/eventlog"
	"syscall"

	"golang.org/x/sys/windows"
)

const addKeyName = `SYSTEM\CurrentControlSet\Services\EventLog\Application`

var categoryCount = len(ktypes.Categories())

// Eventlog provides access to the system log.
type Eventlog struct {
	Handle windows.Handle
}

// Open retrieves a handle to the specified event log.
func Open(source string) (*Eventlog, error) {
	return OpenRemote("", source)
}

// OpenRemote does the same as Open, but on different computer host.
func OpenRemote(host, source string) (*Eventlog, error) {
	if source == "" {
		return nil, errors.New("specify event log source")
	}
	var serverName *uint16
	if host != "" {
		var err error
		serverName, err = syscall.UTF16PtrFromString(host)
		if err != nil {
			return nil, err
		}
	}
	sourceName, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return nil, err
	}
	h, err := windows.RegisterEventSource(serverName, sourceName)
	if err != nil {
		return nil, err
	}
	return &Eventlog{Handle: h}, nil
}

// Close closes event log.
func (l *Eventlog) Close() error {
	return windows.DeregisterEventSource(l.Handle)
}

func (l *Eventlog) report(etype uint16, eid uint32, category uint16, msg []byte) error {
	lines := bytes.Split(msg, []byte("\n"))
	ss := make([]*uint16, len(lines))
	for i, line := range lines {
		// line breaks
		if len(line) == 0 {
			line = []byte("\n")
		}
		s, err := syscall.UTF16PtrFromString(string(line))
		if err != nil {
			continue
		}
		ss[i] = s
	}
	return windows.ReportEvent(l.Handle, etype, category, eid, 0, uint16(len(ss)), 0, &ss[0], nil)
}

// Info writes an information event msg with event id eid to the end of event log.
func (l *Eventlog) Info(eid uint32, category uint16, msg []byte) error {
	return l.report(uint16(eventlog.Info), eid, category, msg)
}

// Warning writes a warning event msg with event id eid to the end of event log.
func (l *Eventlog) Warning(eid uint32, category uint16, msg []byte) error {
	return l.report(uint16(eventlog.Warn), eid, category, msg)
}

// Error writes an error event msg with event id eid to the end of event log.
func (l *Eventlog) Error(eid uint32, category uint16, msg []byte) error {
	return l.report(uint16(eventlog.Erro), eid, category, msg)
}

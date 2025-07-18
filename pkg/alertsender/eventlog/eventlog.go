/*
 * Copyright 2019-2024 by Nedim Sabic Sabic and Contributors
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
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/alertsender"
	evlog "github.com/rabbitstack/fibratus/pkg/util/eventlog"
	"golang.org/x/sys/windows"
	"hash/crc32"
	"strings"
)

const minIDChars = 12

type eventlog struct {
	log    windows.Handle
	config Config
}

func init() {
	alertsender.Register(alertsender.Eventlog, makeSender)
}

func makeSender(config alertsender.Config) (alertsender.Sender, error) {
	c, ok := config.Sender.(Config)
	if !ok {
		return nil, alertsender.ErrInvalidConfig(alertsender.Eventlog)
	}
	sourceName, err := windows.UTF16PtrFromString(evlog.Source)
	if err != nil {
		return nil, fmt.Errorf("could not convert source name: %v", err)
	}

	err = evlog.Install(evlog.Levels)
	if err != nil {
		if !errors.Is(err, evlog.ErrKeyExists) {
			return nil, err
		}
	}

	h, err := windows.RegisterEventSource(nil, sourceName)
	if err != nil {
		return nil, fmt.Errorf("could not register event source: %v", err)
	}
	return &eventlog{log: h, config: c}, nil
}

// Send logs the alert to the eventlog.
func (s *eventlog) Send(alert alertsender.Alert) error {
	var code uint16
	// despite the event id is 4-byte long
	// we can only use 2 bytes to store the
	// event code. Calculate the hash
	// of the event code from alert identifier
	// but keeping in mind collisions are
	// possible since we're mapping a larger
	// space to a smaller one
	if len(alert.ID) > minIDChars {
		// assume alert ID has the UUID format
		// where we build the short version by
		// taking the first 12 characters
		id := strings.ReplaceAll(alert.ID, "-", "")
		h := crc32.ChecksumIEEE([]byte(id[:minIDChars]))
		// take the lower 16 bits of the CRC32 hash
		code = uint16(h & 0xFFFF)
	}

	msg := alert.String(s.config.Verbose)
	// trim null characters to avoid
	// UTF16PtrFromString complaints
	msg = strings.ReplaceAll(msg, "\x00", "")

	m, err := windows.UTF16PtrFromString(msg)
	if err != nil {
		return fmt.Errorf("could not convert eventlog message to UTF16: %v: %s", err, msg)
	}

	return windows.ReportEvent(s.log, windows.EVENTLOG_INFORMATION_TYPE, 0,
		evlog.EventID(windows.EVENTLOG_INFORMATION_TYPE, code),
		uintptr(0),
		1, 0, &m, nil)
}

// Shutdown deregisters the event source.
func (s *eventlog) Shutdown() error {
	if s.log != windows.InvalidHandle {
		return windows.DeregisterEventSource(s.log)
	}
	return nil
}

func (s *eventlog) Type() alertsender.Type { return alertsender.Eventlog }
func (s *eventlog) SupportsMarkdown() bool { return false }

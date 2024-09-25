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
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"golang.org/x/sys/windows"
	"strings"
)

// source represents the event source that generates the alerts
const source = "Fibratus"

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
	sourceName, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return nil, fmt.Errorf("could not convert source name: %v", err)
	}

	h, err := windows.RegisterEventSource(nil, sourceName)
	if err != nil {
		return nil, fmt.Errorf("could not register event source: %v", err)
	}
	return &eventlog{log: h, config: c}, nil
}

// Send logs the alert to the eventlog.
func (s *eventlog) Send(alert alertsender.Alert) error {
	var etype uint16
	switch alert.Severity {
	case alertsender.Normal:
		etype = windows.EVENTLOG_INFORMATION_TYPE
	case alertsender.Medium:
		etype = windows.EVENTLOG_WARNING_TYPE
	case alertsender.High, alertsender.Critical:
		etype = windows.EVENTLOG_ERROR_TYPE
	default:
		etype = windows.EVENTLOG_INFORMATION_TYPE
	}

	msg := alert.String(s.config.Verbose)

	// trim null characters to avoid
	// UTF16PtrFromString complaints
	msg = strings.Replace(msg, "\x00", "", -1)

	m, err := windows.UTF16PtrFromString(msg)
	if err != nil {
		return fmt.Errorf("could not convert eventlog message to UTF16: %v: %s", err, msg)
	}

	return windows.ReportEvent(s.log, etype, 0, 0, uintptr(0), 1, 0, &m, nil)
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

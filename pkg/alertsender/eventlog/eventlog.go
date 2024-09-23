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
	"syscall"
)

// source represents the event source that generates the alerts
const source = "Fibratus"

type eventlog struct {
	log windows.Handle
}

func init() {
	alertsender.Register(alertsender.Eventlog, makeSender)
}

func makeSender(alertsender.Config) (alertsender.Sender, error) {
	sourceName, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return nil, fmt.Errorf("could not convert source name: %v", err)
	}

	h, err := windows.RegisterEventSource(nil, sourceName)
	if err != nil {
		return nil, fmt.Errorf("could not register event source: %v", err)
	}
	return &eventlog{log: h}, nil
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

	msg := fmt.Sprintf("%s\n\n%s", alert.Title, alert.Text)
	lines := strings.Split(msg, "\n")
	ss := make([]*uint16, len(lines))
	for i, line := range lines {
		// line breaks
		if len(line) == 0 {
			line = "\n"
		}
		s, err := syscall.UTF16PtrFromString(line)
		if err != nil {
			continue
		}
		ss[i] = s
	}
	m, err := windows.UTF16PtrFromString(msg)
	if err != nil {
		return fmt.Errorf("could not convert eventlog message to UTF16: %v", err)
	}
	msgs := []*uint16{m}

	return windows.ReportEvent(s.log, etype, 0, 0, uintptr(0), uint16(len(msgs)), 0, &msgs[0], nil)
}

// Shutdown deregisters the event source.
func (s *eventlog) Shutdown() error {
	if s.log != windows.InvalidHandle {
		return windows.DeregisterEventSource(s.log)
	}
	return nil
}

func (s *eventlog) Type() alertsender.Type { return alertsender.Systray }
func (s *eventlog) SupportsMarkdown() bool { return true }

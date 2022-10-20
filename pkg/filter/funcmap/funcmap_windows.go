/*
 * Copyright 2020-2021 by Nedim Sabic Sabic
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

package funcmap

import (
	"fmt"
	"github.com/Masterminds/sprig/v3"
	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	log "github.com/sirupsen/logrus"
	"strings"
	"syscall"
	"text/template"
)

// New returns the template func map
// populated with some useful template functions
// that can be used in filter actions. Some functions
// are late-bound, so we merely provide a declaration.
// The real function is attached when the filter action
// is triggered.
func New() template.FuncMap {
	f := sprig.TxtFuncMap()

	extra := template.FuncMap{
		// This is a placeholder for the functions that might be
		// late-bound to a template. By declaring them here, we
		// can still execute the template associated with the
		// filter action to ensure template syntax is correct
		"emit": func(title string, text string, args ...string) string { return "" },
		"kill": func(pid uint32) string { return "" },
		"stringify": func(in []interface{}) string {
			values := make([]string, 0)
			for _, e := range in {
				s, ok := e.(string)
				if !ok {
					continue
				}
				values = append(values, fmt.Sprintf("'%s'", s))
			}
			return fmt.Sprintf("(%s)", strings.Join(values, ", "))
		},
		"printevt":  func(kevts ...*kevent.Kevent) string { return "" },
		"printevts": func(kevts map[string]*kevent.Kevent) string { return "" },
	}

	for k, v := range extra {
		f[k] = v
	}

	return f
}

// InitFuncs assigns late-bound functions to the func map.
func InitFuncs(funcMap template.FuncMap) {
	funcMap["emit"] = emit
	funcMap["kill"] = kill
	funcMap["printevt"] = printEvt
	funcMap["printevts"] = printEvts
}

// emit sends an alert via all configured alert senders.
func emit(title string, text string, args ...string) string {
	log.Debugf("sending alert: %s. Text: %s", title, text)

	senders := alertsender.FindAll()
	if len(senders) == 0 {
		return "no alertsenders registered. Alert won't be sent"
	}

	severity := "normal"
	tags := make([]string, 0)
	if len(args) > 0 {
		severity = args[0]
	}
	if len(args) > 1 {
		tags = args[1:]
	}

	for _, s := range senders {
		alert := alertsender.NewAlert(
			title,
			text,
			tags,
			alertsender.ParseSeverityFromString(severity),
		)
		if err := s.Send(alert); err != nil {
			log.Warnf("unable to emit alert from rule: %v", err)
		}
	}
	return ""
}

// kill terminates a process with specified pid.
func kill(pid uint32) string {
	h, err := syscall.OpenProcess(syscall.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return fmt.Sprintf("couldn't open pid %d for termination: %v", pid, err)
	}
	defer func() {
		_ = syscall.CloseHandle(h)
	}()
	err = syscall.TerminateProcess(h, uint32(1))
	if err != nil {
		return fmt.Sprintf("fail to kill pid %d: %v", pid, err)
	}
	return ""
}

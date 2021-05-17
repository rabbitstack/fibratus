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
	log "github.com/sirupsen/logrus"
	"syscall"
	"text/template"
)

// New returns the template func map
// populated with some useful template functions
// that can be used in filter actions.
func New() template.FuncMap {
	f := sprig.TxtFuncMap()

	extra := template.FuncMap{
		// Here we declare extra functions to
		// use them from the group file templates
		"emitAlert": emitAlert,
		"kill":      kill,
	}

	for k, v := range extra {
		f[k] = v
	}

	return f
}

// emitAlert sends an alert via all configured alert senders.
func emitAlert(title string, text string, args ...string) string {
	senders := alertsender.FindAll()
	if len(senders) == 0 {
		log.Warn("no alertsenders registered. Alert won't be sent")
		return ""
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
			log.Warnf("unable to emit alert from filter: %v", err)
		}
	}
	return ""
}

// kill terminates a process with specified pid.
func kill(pid int) string {
	h, err := syscall.OpenProcess(syscall.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return fmt.Sprintf("couldn't open pid %d for terminating: %v", pid, err)
	}
	defer syscall.CloseHandle(h)
	err = syscall.TerminateProcess(h, uint32(1))
	if err != nil {
		return fmt.Sprintf("fail to kill pid %d: %v", pid, err)
	}
	return ""
}

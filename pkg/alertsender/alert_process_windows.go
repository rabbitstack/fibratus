//go:build windows

/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
 * Copyright 2026 by Mostafa Moradian
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

package alertsender

import (
	"fmt"

	"github.com/rabbitstack/fibratus/pkg/event"
)

type alertProcess struct {
	PID            event.PID `json:"pid"`
	TID            event.TID `json:"tid"`
	PPID           event.PID `json:"ppid"`
	Name           string    `json:"name"`
	Exe            string    `json:"exe"`
	Cmdline        string    `json:"cmdline,omitempty"`
	Pname          string    `json:"parent_name,omitempty"`
	Pcmdline       string    `json:"parent_cmdline,omitempty"`
	Cwd            string    `json:"cwd,omitempty"`
	SID            string    `json:"sid"`
	Username       string    `json:"username"`
	Domain         string    `json:"domain"`
	SessionID      uint32    `json:"session_id"`
	IntegrityLevel string    `json:"integrity_level"`
	IsWOW64        bool      `json:"is_wow64"`
	IsPackaged     bool      `json:"is_packaged"`
	IsProtected    bool      `json:"is_protected"`
	Ancestors      []string  `json:"ancestors"`
}

func newAlertProcess(e *event.Event) *alertProcess {
	if e.PS == nil {
		return nil
	}
	proc := &alertProcess{
		PID:            e.PS.PID,
		TID:            e.Tid,
		PPID:           e.PS.Ppid,
		Name:           e.PS.Name,
		Exe:            e.PS.Exe,
		Cmdline:        e.PS.Cmdline,
		Cwd:            e.PS.Cwd,
		SID:            e.PS.SID,
		Username:       e.PS.Username,
		Domain:         e.PS.Domain,
		SessionID:      e.PS.SessionID,
		IntegrityLevel: e.PS.TokenIntegrityLevel,
		IsWOW64:        e.PS.IsWOW64,
		IsPackaged:     e.PS.IsPackaged,
		IsProtected:    e.PS.IsProtected,
		Ancestors:      make([]string, 0),
	}
	proc.Ancestors = append(proc.Ancestors, e.PS.Ancestors()...)
	if e.PS.Parent != nil {
		proc.Pname = e.PS.Parent.Name
		proc.Pcmdline = e.PS.Parent.Cmdline
	}
	return proc
}

func alertCallstack(e *event.Event) []string {
	callstack := make([]string, 0, len(e.Callstack))
	for i := range e.Callstack {
		frame := e.Callstack[len(e.Callstack)-i-1]
		callstack = append(callstack, fmt.Sprintf("%v %s!%s", frame.Addr, frame.Module, frame.Symbol))
	}
	return callstack
}

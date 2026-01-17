/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/renderer/html"
)

// Severity is the type alias for alert's severity level.
type Severity uint8

const (
	// Normal designates alert's normal level
	Normal Severity = iota
	// Medium designates alert's medium level
	Medium
	// High designates alert's high level
	High
	// Critical designates alert's critical level
	Critical
)

// String returns severity human-friendly name.
func (s Severity) String() string {
	switch s {
	case Normal:
		return "low"
	case Medium:
		return "medium"
	case High:
		return "high"
	case Critical:
		return "critical"
	default:
		return "unknown"
	}
}

// StringToSeverityDecodeHook converts severity string to integer.
func StringToSeverityDecodeHook() mapstructure.DecodeHookFuncType {
	return func(
		from reflect.Type,
		to reflect.Type,
		data any,
	) (any, error) {
		if from.Kind() != reflect.String {
			return data, nil
		}

		if to != reflect.TypeOf(Severity(0)) {
			return data, nil
		}

		return ParseSeverityFromString(data.(string)), nil
	}
}

// ParseSeverityFromString parses the severity from the string representation.
func ParseSeverityFromString(sever string) Severity {
	switch sever {
	case "normal", "Normal", "NORMAL", "low", "LOW":
		return Normal
	case "medium", "Medium", "MEDIUM":
		return Medium
	case "high", "High", "HIGH":
		return High
	case "critical", "Critical", "CRITICAL":
		return Critical
	default:
		return Normal
	}
}

// Alert encapsulates the state of an alert.
type Alert struct {
	// ID identifies the alert. Note that the ID may not be unique
	// for every distinct instance of the generated alert. For runtime
	// rules, the alert id equals to the rule identifier.
	ID string
	// Title is the short title that summarizes the purpose of the alert.
	Title string
	// Text is the longer textual content that further explains what this alert is about.
	Text string
	// Tags contains a sequence of tags for categorizing the alerts.
	Tags []string
	// Labels is an arbitrary collection of key-value pairs.
	Labels map[string]string
	// Description represents a longer explanation of the alert. It is
	// typically a description of adversary tactics, techniques or any
	// information valuable to the analyst.
	Description string
	// Severity determines the severity of this alert.
	Severity Severity
	// Events contains a list of events that trigger the alert.
	Events []*event.Event
}

// String returns the alert string representation. If verbose
// argument is set to true, the event summary is included in
// the alert.
func (a Alert) String(verbose bool) string {
	if verbose {
		var b strings.Builder
		if len(a.Events) > 1 {
			b.WriteString("System events involved in this alert:\n\n")
		} else {
			b.WriteString("System event involved in this alert:\n\n")
		}
		for n, evt := range a.Events {
			b.WriteString(fmt.Sprintf("\tEvent #%d:\n", n+1))
			b.WriteString(strings.TrimSuffix(evt.StringShort(), "\t"))
		}
		if a.Text == "" {
			return fmt.Sprintf("%s\n\nSeverity: %s\n\n%s", a.Title, a.Severity, b.String())
		}
		return fmt.Sprintf("%s\n\n%s\n\nSeverity: %s\n\n%s", a.Title, a.Text, a.Severity, b.String())
	}

	if a.Text == "" {
		return a.Title
	}
	return fmt.Sprintf("%s\n\n%s", a.Title, a.Text)
}

// MDToHTML converts alert's text Markdown elements to HTML blocks.
func (a *Alert) MDToHTML() error {
	md := goldmark.New(
		goldmark.WithExtensions(extension.GFM),
		goldmark.WithRendererOptions(html.WithUnsafe()),
	)
	var w bytes.Buffer
	err := md.Convert([]byte(a.Text), &w)
	if err != nil {
		return err
	}
	a.Text = w.String()
	return nil
}

// MarshalJSON encodes the alert to JSON format.
func (a Alert) MarshalJSON() ([]byte, error) {
	var msg = &struct {
		ID          string            `json:"id"`
		Title       string            `json:"title"`
		Severity    string            `json:"severity"`
		Text        string            `json:"text,omitempty"`
		Description string            `json:"description"`
		Labels      map[string]string `json:"labels,omitempty"`
		Events      []struct {
			Name      string         `json:"name"`
			Category  string         `json:"category"`
			Timestamp time.Time      `json:"timestamp"`
			Params    map[string]any `json:"params"`
			Callstack []string       `json:"callstack,omitempty"`
			Proc      *struct {
				PID            uint32   `json:"pid"`
				TID            uint32   `json:"tid"`
				PPID           uint32   `json:"ppid"`
				Name           string   `json:"name"`
				Exe            string   `json:"exe"`
				Cmdline        string   `json:"cmdline,omitempty"`
				Pname          string   `json:"parent_name,omitempty"`
				Pcmdline       string   `json:"parent_cmdline,omitempty"`
				Cwd            string   `json:"cwd,omitempty"`
				SID            string   `json:"sid"`
				Username       string   `json:"username"`
				Domain         string   `json:"domain"`
				SessionID      uint32   `json:"session_id"`
				IntegrityLevel string   `json:"integrity_level"`
				IsWOW64        bool     `json:"is_wow64"`
				IsPackaged     bool     `json:"is_packaged"`
				IsProtected    bool     `json:"is_protected"`
				Ancestors      []string `json:"ancestors"`
			} `json:"proc,omitempty"`
		} `json:"events"`
	}{
		ID:          a.ID,
		Title:       a.Title,
		Severity:    a.Severity.String(),
		Text:        a.Text,
		Description: a.Description,
		Labels:      a.Labels,
	}

	events := make([]struct {
		Name      string         `json:"name"`
		Category  string         `json:"category"`
		Timestamp time.Time      `json:"timestamp"`
		Params    map[string]any `json:"params"`
		Callstack []string       `json:"callstack,omitempty"`
		Proc      *struct {
			PID            uint32   `json:"pid"`
			TID            uint32   `json:"tid"`
			PPID           uint32   `json:"ppid"`
			Name           string   `json:"name"`
			Exe            string   `json:"exe"`
			Cmdline        string   `json:"cmdline,omitempty"`
			Pname          string   `json:"parent_name,omitempty"`
			Pcmdline       string   `json:"parent_cmdline,omitempty"`
			Cwd            string   `json:"cwd,omitempty"`
			SID            string   `json:"sid"`
			Username       string   `json:"username"`
			Domain         string   `json:"domain"`
			SessionID      uint32   `json:"session_id"`
			IntegrityLevel string   `json:"integrity_level"`
			IsWOW64        bool     `json:"is_wow64"`
			IsPackaged     bool     `json:"is_packaged"`
			IsProtected    bool     `json:"is_protected"`
			Ancestors      []string `json:"ancestors"`
		} `json:"proc,omitempty"`
	}, 0, len(a.Events))

	for _, e := range a.Events {
		var evt = struct {
			Name      string         `json:"name"`
			Category  string         `json:"category"`
			Timestamp time.Time      `json:"timestamp"`
			Params    map[string]any `json:"params"`
			Callstack []string       `json:"callstack,omitempty"`
			Proc      *struct {
				PID            uint32   `json:"pid"`
				TID            uint32   `json:"tid"`
				PPID           uint32   `json:"ppid"`
				Name           string   `json:"name"`
				Exe            string   `json:"exe"`
				Cmdline        string   `json:"cmdline,omitempty"`
				Pname          string   `json:"parent_name,omitempty"`
				Pcmdline       string   `json:"parent_cmdline,omitempty"`
				Cwd            string   `json:"cwd,omitempty"`
				SID            string   `json:"sid"`
				Username       string   `json:"username"`
				Domain         string   `json:"domain"`
				SessionID      uint32   `json:"session_id"`
				IntegrityLevel string   `json:"integrity_level"`
				IsWOW64        bool     `json:"is_wow64"`
				IsPackaged     bool     `json:"is_packaged"`
				IsProtected    bool     `json:"is_protected"`
				Ancestors      []string `json:"ancestors"`
			} `json:"proc,omitempty"`
		}{
			Name:      e.Name,
			Category:  string(e.Category),
			Timestamp: e.Timestamp,
			Params:    make(map[string]any),
			Callstack: make([]string, 0, len(e.Callstack)),
		}

		// populate event parameters
		for _, param := range e.Params {
			if param.Type == params.Bool || param.Type == params.PID ||
				param.Type == params.TID || param.Type == params.Port || param.IsNumber() {
				evt.Params[param.Name] = param.Value
			} else {
				evt.Params[param.Name] = param.String()
			}
		}

		// populate callstack
		for i := range e.Callstack {
			frame := e.Callstack[len(e.Callstack)-i-1]
			evt.Callstack = append(evt.Callstack, fmt.Sprintf("%s %s!%s", frame.Addr, frame.Module, frame.Symbol))
		}

		ps := e.PS
		if ps != nil {
			evt.Proc = &struct {
				PID            uint32   `json:"pid"`
				TID            uint32   `json:"tid"`
				PPID           uint32   `json:"ppid"`
				Name           string   `json:"name"`
				Exe            string   `json:"exe"`
				Cmdline        string   `json:"cmdline,omitempty"`
				Pname          string   `json:"parent_name,omitempty"`
				Pcmdline       string   `json:"parent_cmdline,omitempty"`
				Cwd            string   `json:"cwd,omitempty"`
				SID            string   `json:"sid"`
				Username       string   `json:"username"`
				Domain         string   `json:"domain"`
				SessionID      uint32   `json:"session_id"`
				IntegrityLevel string   `json:"integrity_level"`
				IsWOW64        bool     `json:"is_wow64"`
				IsPackaged     bool     `json:"is_packaged"`
				IsProtected    bool     `json:"is_protected"`
				Ancestors      []string `json:"ancestors"`
			}{
				PID:            ps.PID,
				TID:            e.Tid,
				PPID:           ps.Ppid,
				Name:           ps.Name,
				Exe:            ps.Exe,
				Cmdline:        ps.Cmdline,
				Cwd:            ps.Cwd,
				SID:            ps.SID,
				Username:       ps.Username,
				Domain:         ps.Domain,
				SessionID:      ps.SessionID,
				IntegrityLevel: ps.TokenIntegrityLevel,
				IsWOW64:        ps.IsWOW64,
				IsPackaged:     ps.IsPackaged,
				IsProtected:    ps.IsProtected,
				Ancestors:      ps.Ancestors(),
			}
			if ps.Parent != nil {
				evt.Proc.Pname = ps.Parent.Name
				evt.Proc.Pcmdline = ps.Parent.Cmdline
			}
		}

		events = append(events, evt)
	}
	msg.Events = events

	return json.Marshal(msg)
}

// NewAlert builds a new alert.
func NewAlert(title, text string, tags []string, severity Severity) Alert {
	return Alert{Title: title, Text: text, Tags: tags, Severity: severity}
}

// NewAlertWithEvents builds a new alert with associated events.
func NewAlertWithEvents(title, text string, tags []string, severity Severity, evts []*event.Event) Alert {
	return Alert{Title: title, Text: text, Tags: tags, Severity: severity, Events: evts}
}

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
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/renderer/html"
	"strings"
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
	Events []*kevent.Kevent
}

// String returns the alert string representation. If verbose
// argument is set to true, the event summary is included in
// the alert.
func (a Alert) String(verbose bool) string {
	if verbose {
		var b strings.Builder
		for n, evt := range a.Events {
			b.WriteString(fmt.Sprintf("Event #%d:\n", n+1))
			b.WriteString(evt.String())
		}
		if a.Text == "" {
			return fmt.Sprintf("%s\n\n%s", a.Title, b.String())
		}
		return fmt.Sprintf("%s\n\n%s\n\n%s", a.Title, a.Text, b.String())
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

// NewAlert builds a new alert.
func NewAlert(title, text string, tags []string, severity Severity) Alert {
	return Alert{Title: title, Text: text, Tags: tags, Severity: severity}
}

// NewAlertWithEvents builds a new alert with associated events.
func NewAlertWithEvents(title, text string, tags []string, severity Severity, evts []*kevent.Kevent) Alert {
	return Alert{Title: title, Text: text, Tags: tags, Severity: severity, Events: evts}
}

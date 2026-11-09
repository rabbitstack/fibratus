/*
 * Copyright 2021-present by Nedim Sabic Sabic
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

package etw

import (
	"fmt"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"github.com/rabbitstack/fibratus/pkg/eval"
	"github.com/rabbitstack/fibratus/pkg/rules"
	"github.com/rabbitstack/fibratus/pkg/util/markdown"
	log "github.com/sirupsen/logrus"
)

// RuleAlerter is the implicit action that sends the rule alert via
// all configured alert senders. It implements the rules.Alerter interface.
type RuleAlerter struct {
	// senders returns the alert senders to dispatch the alert to
	senders func() []alertsender.Sender
}

// NewRuleAlerter creates the alerter that uses the registered alert senders.
func NewRuleAlerter() *RuleAlerter {
	return &RuleAlerter{senders: alertsender.FindAll}
}

// Alert sends the alert about the rule match. The text of the alert is the
// rule output with the field modifiers replaced by the event values.
func (a *RuleAlerter) Alert(m rules.RuleMatch) error {
	rule := m.Rule

	var b strings.Builder
	for _, evt := range m.Events {
		b.WriteString(evt.String())
		b.WriteByte('\n')
	}
	text := eval.InterpolateFields(rule.Output, m.Events)
	log.Infof("sending alert: [%s]. Text: %s Event(s): %s", rule.Name, text, b.String())

	senders := a.senders()
	if len(senders) == 0 {
		return fmt.Errorf("no alertsenders registered. Alert won't be sent")
	}

	var errs []string
	for _, sender := range senders {
		alert := alertsender.NewAlert(
			rule.Name,
			text,
			rule.Tags,
			alertsender.ParseSeverityFromString(rule.Severity),
		)

		alert.ID = string(rule.ID)
		alert.Events = m.Events
		alert.Labels = rule.Labels
		alert.Description = rule.Description

		// strip markdown if not supported by the sender
		if !sender.SupportsMarkdown() {
			alert.Text = markdown.Strip(alert.Text)
		}

		// a failing sender must not prevent the other senders from being notified
		if err := sender.Send(alert); err != nil {
			errs = append(errs, fmt.Sprintf("unable to emit alert from rule via [%s] sender: %v", sender.Type(), err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}

	return nil
}

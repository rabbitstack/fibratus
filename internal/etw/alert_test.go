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
	"errors"
	"testing"

	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/policy"
	"github.com/rabbitstack/fibratus/pkg/rules"
	"github.com/rabbitstack/fibratus/pkg/util/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeSender struct {
	markdown bool
	err      error
	alerts   []alertsender.Alert
}

func (s *fakeSender) Send(a alertsender.Alert) error { s.alerts = append(s.alerts, a); return s.err }
func (s *fakeSender) Type() alertsender.Type         { return alertsender.Noop }
func (s *fakeSender) Shutdown() error                { return nil }
func (s *fakeSender) SupportsMarkdown() bool         { return s.markdown }

func newTestAlerter(senders ...alertsender.Sender) *RuleAlerter {
	return &RuleAlerter{senders: func() []alertsender.Sender { return senders }}
}

func alertMatch(t *testing.T) rules.RuleMatch {
	t.Helper()
	rule, err := rules.NewRule(&policy.RuleDef{
		ID:          "rule-id",
		Name:        "Suspicious file",
		Description: "details",
		Condition:   "evt.name = 'CreateFile'",
		Output:      "**file** created by %ps.name",
		Severity:    "high",
		Tags:        []string{"tag"},
		Labels:      map[string]string{"tactic.id": "TA0002"},
	}, nil)
	require.NoError(t, err)
	evt := testutil.MakeEvent(event.CreateFile, testutil.WithPS(testutil.MakePS(1, "cmd.exe")))
	return rules.RuleMatch{Rule: rule, Events: []*event.Event{evt}}
}

func TestRuleAlerter(t *testing.T) {
	md := &fakeSender{markdown: true}
	plain := &fakeSender{}
	require.NoError(t, newTestAlerter(md, plain).Alert(alertMatch(t)))

	for _, s := range []*fakeSender{md, plain} {
		require.Len(t, s.alerts, 1)
		a := s.alerts[0]
		assert.Equal(t, "rule-id", a.ID)
		assert.Equal(t, "Suspicious file", a.Title)
		assert.Equal(t, "details", a.Description)
		assert.Equal(t, []string{"tag"}, a.Tags)
		assert.Equal(t, map[string]string{"tactic.id": "TA0002"}, a.Labels)
		assert.Equal(t, alertsender.High, a.Severity)
		assert.Len(t, a.Events, 1)
	}
	// the markdown is stripped only for the senders that don't support it
	assert.Equal(t, "**file** created by cmd.exe", md.alerts[0].Text)
	assert.Equal(t, "file created by cmd.exe", plain.alerts[0].Text)
}

func TestRuleAlerterNoSenders(t *testing.T) {
	err := newTestAlerter().Alert(alertMatch(t))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no alertsenders registered")
}

func TestRuleAlerterFailingSenderDoesNotBlockOthers(t *testing.T) {
	failing := &fakeSender{err: errors.New("smtp down")}
	ok := &fakeSender{}
	err := newTestAlerter(failing, ok).Alert(alertMatch(t))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "smtp down")
	assert.Len(t, ok.alerts, 1)
}

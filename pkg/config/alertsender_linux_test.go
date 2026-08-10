//go:build linux

/*
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

package config

import (
	"testing"

	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"github.com/rabbitstack/fibratus/pkg/alertsender/mail"
	"github.com/rabbitstack/fibratus/pkg/alertsender/slack"
	"github.com/stretchr/testify/require"
)

func TestAlertSendersLinux(t *testing.T) {
	c := NewWithOpts(WithRun())
	c.viper.Set("alertsenders", map[string]interface{}{
		"mail": map[string]interface{}{
			"enabled": true,
			"host":    "smtp.example.com",
		},
		"slack": map[string]interface{}{
			"enabled": true,
			"url":     "https://example.com/hook",
		},
		"eventlog": map[string]interface{}{"enabled": true},
		"systray":  map[string]interface{}{"enabled": true},
	})

	require.NoError(t, c.tryLoadAlertSenders())
	require.Len(t, c.Alertsenders, 2)
	for _, sender := range c.Alertsenders {
		switch sender.Type {
		case alertsender.Mail:
			require.IsType(t, mail.Config{}, sender.Sender)
		case alertsender.Slack:
			require.IsType(t, slack.Config{}, sender.Sender)
		default:
			require.Failf(t, "unexpected sender", "%v", sender.Type)
		}
	}
}

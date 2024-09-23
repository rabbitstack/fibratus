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

package config

import (
	"github.com/rabbitstack/fibratus/pkg/aggregator/transformers"
	"github.com/rabbitstack/fibratus/pkg/aggregator/transformers/rename"
	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"github.com/rabbitstack/fibratus/pkg/alertsender/eventlog"
	"github.com/rabbitstack/fibratus/pkg/alertsender/mail"
	"github.com/rabbitstack/fibratus/pkg/alertsender/slack"
	"github.com/rabbitstack/fibratus/pkg/alertsender/systray"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestNewFromYamlFile(t *testing.T) {
	c := NewWithOpts(WithRun())

	err := c.flags.Parse([]string{"--config-file=_fixtures/fibratus.yml"})
	require.NoError(t, c.viper.BindPFlags(c.flags))
	require.NoError(t, err)
	require.NoError(t, c.TryLoadFile(c.GetConfigFile()))

	require.NoError(t, c.Init())

	errs := c.Validate()

	require.Empty(t, errs)

	assert.Equal(t, time.Millisecond*230, c.Aggregator.FlushPeriod)
	assert.Equal(t, time.Second*8, c.Aggregator.FlushTimeout)

	assert.Len(t, c.Alertsenders, 4)

	for _, c := range c.Alertsenders {
		switch c.Type {
		case alertsender.Slack:
			assert.IsType(t, slack.Config{}, c.Sender)
		case alertsender.Mail:
			assert.IsType(t, mail.Config{}, c.Sender)
			mailConfig := c.Sender.(mail.Config)
			assert.Equal(t, "smtp.gmail.com", mailConfig.Host)
			assert.Equal(t, 587, mailConfig.Port)
			assert.Equal(t, "bunny", mailConfig.User)
			assert.Equal(t, "changeit", mailConfig.Pass)
			assert.Equal(t, "bunny@gmail.com", mailConfig.From)
			assert.Equal(t, []string{"bunny@gmail.com", "rabbit@gmail.com", "cuniculus@gmail.com"}, mailConfig.To)
		case alertsender.Systray:
			assert.IsType(t, systray.Config{}, c.Sender)
			systrayConfig := c.Sender.(systray.Config)
			assert.True(t, systrayConfig.Enabled)
			assert.True(t, systrayConfig.Sound)
			assert.False(t, systrayConfig.QuietMode)
		case alertsender.Eventlog:
			assert.IsType(t, eventlog.Config{}, c.Sender)
			eventlogConfig := c.Sender.(eventlog.Config)
			assert.True(t, eventlogConfig.Enabled)
		}
	}

	assert.Equal(t, "npipe:///fibratus", c.API.Transport)
	assert.Equal(t, time.Second*5, c.API.Timeout)
	assert.True(t, c.DebugPrivilege)

	assert.Equal(t, "top_netio", c.Filament.Name)

	require.Len(t, c.Transformers, 2)

	for _, tr := range c.Transformers {
		switch tr.Type {
		case transformers.Rename:
			rconfig := tr.Transformer.(rename.Config)
			assert.Len(t, rconfig.Kparams, 2)
			r1 := rconfig.Kparams[0]
			assert.Equal(t, "b", r1.New)
		}
	}

	assert.True(t, c.Yara.Enabled)

	require.Len(t, c.Yara.Rule.Paths, 1)
	assert.Len(t, c.Yara.Rule.Strings, 1)

	assert.Equal(t, "C:\\yara-rules", c.Yara.Rule.Paths[0].Path)
	assert.Equal(t, "default", c.Yara.Rule.Paths[0].Namespace)
}

func TestNewFromJsonFile(t *testing.T) {
	c := NewWithOpts(WithRun())

	err := c.flags.Parse([]string{"--config-file=_fixtures/fibratus.json"})
	require.NoError(t, c.viper.BindPFlags(c.flags))
	require.NoError(t, err)
	require.NoError(t, c.TryLoadFile(c.GetConfigFile()))

	require.NoError(t, c.Init())

	errs := c.Validate()

	require.Empty(t, errs)

	assert.Equal(t, time.Millisecond*230, c.Aggregator.FlushPeriod)
	assert.Equal(t, time.Second*8, c.Aggregator.FlushTimeout)
}

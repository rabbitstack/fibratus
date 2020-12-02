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

package slack

import "github.com/spf13/pflag"

const (
	enabled   = "alertsenders.slack.enabled"
	url       = "alertsenders.slack.url"
	workspace = "alertsenders.slack.workspace"
	channel   = "alertsenders.slack.channel"
	botemoji  = "alertsenders.slack.emoji"
)

// Config stores the settings that dictate the behaviour of the Slack alert sender.
type Config struct {
	// URL represents the Webhook URL of the workspace where alerts will be dispatched.
	URL string `mapstructure:"url"`
	// Workspace designates the Slack workspace where alerts will be routed.
	Workspace string `mapstructure:"workspace"`
	// Channel is the slack channel in which to post alerts.
	Channel string `mapstructure:"channel"`
	// BotEmoji is the emoji icon for the Slack bot.
	BotEmoji string `mapstructure:"emoji"`
	// Enabled determines if Slack alert sender is enabled.
	Enabled bool `mapstructure:"enabled"`
}

// AddFlags registers persistent flags.
func AddFlags(flags *pflag.FlagSet) {
	flags.Bool(enabled, false, "Determines whether Slack alert sender is enabled")
	flags.String(url, "", "Represents the Webhook URL of the workspace where alerts will be dispatched")
	flags.String(workspace, "", "Designates the Slack workspace where alerts will be routed")
	flags.String(channel, "", "Represents the slack channel in which to post alerts")
	flags.String(botemoji, "", "Represents the emoji icon for the Slack bot")
}

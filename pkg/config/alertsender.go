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
	"errors"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"github.com/rabbitstack/fibratus/pkg/alertsender/eventlog"
	"github.com/rabbitstack/fibratus/pkg/alertsender/mail"
	"github.com/rabbitstack/fibratus/pkg/alertsender/slack"
	"github.com/rabbitstack/fibratus/pkg/alertsender/systray"
	"reflect"
)

var errNoAlertsendersSection = errors.New("no alertsenders section in config")

var errAlertsenderConfig = func(sender string, err error) error {
	return fmt.Errorf("%s alert sender invalid config: %v", sender, err)
}

func (c *Config) tryLoadAlertSenders() error {
	if c.ForwardMode || c.IsCaptureSet() {
		// In event forwarding mode or capture control, alert senders are useless
		return nil
	}

	configs := make([]alertsender.Config, 0)
	alertsenders := c.viper.AllSettings()["alertsenders"]
	if alertsenders == nil {
		return errNoAlertsendersSection
	}

	mapping, ok := alertsenders.(map[string]interface{})
	if !ok {
		return fmt.Errorf("expected map[string]interface{} type for alertsenders but found %s", reflect.TypeOf(alertsenders))
	}

	for typ, config := range mapping {
		switch typ {
		case "mail":
			var mailConfig mail.Config
			if err := decode(config, &mailConfig); err != nil {
				return errAlertsenderConfig(typ, err)
			}
			if !mailConfig.Enabled {
				continue
			}
			config := alertsender.Config{
				Type:   alertsender.Mail,
				Sender: mailConfig,
			}
			configs = append(configs, config)
		case "slack":
			var slackConfig slack.Config
			if err := decode(config, &slackConfig); err != nil {
				return errAlertsenderConfig(typ, err)
			}
			if !slackConfig.Enabled {
				continue
			}
			config := alertsender.Config{
				Type:   alertsender.Slack,
				Sender: slackConfig,
			}
			configs = append(configs, config)
		case "systray":
			var systrayConfig systray.Config
			if err := decode(config, &systrayConfig); err != nil {
				return errAlertsenderConfig(typ, err)
			}
			if !systrayConfig.Enabled {
				continue
			}
			config := alertsender.Config{
				Type:   alertsender.Systray,
				Sender: systrayConfig,
			}
			configs = append(configs, config)

		case "eventlog":
			var eventlogConfig eventlog.Config
			if err := decode(config, &eventlogConfig); err != nil {
				return errAlertsenderConfig(typ, err)
			}
			if !eventlogConfig.Enabled {
				continue
			}
			config := alertsender.Config{
				Type:   alertsender.Eventlog,
				Sender: eventlogConfig,
			}
			configs = append(configs, config)
		}
	}

	c.Alertsenders = configs

	return nil
}

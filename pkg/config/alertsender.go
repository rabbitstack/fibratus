/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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
	"errors"
	"fmt"
	"reflect"

	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"github.com/rabbitstack/fibratus/pkg/alertsender/mail"
	"github.com/rabbitstack/fibratus/pkg/alertsender/slack"
)

var ErrNoAlertsendersSection = errors.New("no alertsenders section in config")

var ErrAlertsenderConfig = func(sender string, err error) error {
	return fmt.Errorf("%s alert sender invalid config: %v", sender, err)
}

var senders = alertsender.ConfigLoaders{}

func init() {
	senders.Register(alertsender.Mail, alertsender.LoadFromConfig(alertsender.Mail, func(c mail.Config) bool { return c.Enabled }))
	senders.Register(alertsender.Slack, alertsender.LoadFromConfig(alertsender.Slack, func(c slack.Config) bool { return c.Enabled }))
}

// TryLoadAlertSenders loads configs for all registered alert senders.
func (c *BaseConfig) TryLoadAlertSenders() error {
	if c.ForwardMode || c.IsCaptureSet() {
		// In event forwarding mode or capture control, alert senders are useless
		return nil
	}

	alertsenders := c.viper.AllSettings()["alertsenders"]
	if alertsenders == nil {
		return ErrNoAlertsendersSection
	}

	mapping, ok := alertsenders.(map[string]any)
	if !ok {
		return fmt.Errorf("expected map[string]interface{} type for alertsenders but found %s", reflect.TypeOf(alertsenders))
	}

	configs := make([]alertsender.Config, 0, len(mapping))
	for name, raw := range mapping {
		loader, ok := senders[alertsender.ToType(name)]
		if !ok {
			return fmt.Errorf("unknown alertsender type %q", name)
		}
		cfg, enabled, err := loader(raw)
		if err != nil {
			return ErrAlertsenderConfig(name, err)
		}
		if !enabled {
			continue
		}
		configs = append(configs, cfg)
	}
	c.Alertsenders = configs

	return nil
}

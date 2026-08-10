//go:build windows

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
	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"github.com/rabbitstack/fibratus/pkg/alertsender/eventlog"
	"github.com/rabbitstack/fibratus/pkg/alertsender/systray"
)

func (c *Config) loadPlatformAlertSender(typ string, config interface{}, configs *[]alertsender.Config) error {
	switch typ {
	case "systray":
		var systrayConfig systray.Config
		if err := decode(config, &systrayConfig); err != nil {
			return errAlertsenderConfig(typ, err)
		}
		if !systrayConfig.Enabled {
			return nil
		}
		*configs = append(*configs, alertsender.Config{
			Type:   alertsender.Systray,
			Sender: systrayConfig,
		})
	case "eventlog":
		var eventlogConfig eventlog.Config
		if err := decode(config, &eventlogConfig); err != nil {
			return errAlertsenderConfig(typ, err)
		}
		if !eventlogConfig.Enabled {
			return nil
		}
		*configs = append(*configs, alertsender.Config{
			Type:   alertsender.Eventlog,
			Sender: eventlogConfig,
		})
	}
	return nil
}

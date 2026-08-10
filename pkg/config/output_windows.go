//go:build windows

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
	"github.com/rabbitstack/fibratus/pkg/outputs"
	"github.com/rabbitstack/fibratus/pkg/outputs/eventlog"
	"github.com/rabbitstack/fibratus/pkg/outputs/null"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/svc"
)

func (c *Config) loadPlatformOutput(output outputs.Type, typ string, config interface{}) error {
	if output != outputs.Eventlog {
		return nil
	}
	var eventlogConfig eventlog.Config
	if err := decode(config, &eventlogConfig); err != nil {
		return errOutputConfig(typ, err)
	}
	if eventlogConfig.Enabled {
		c.Output.Type, c.Output.Output = outputs.Eventlog, eventlogConfig
	}
	return nil
}

func (c *Config) adjustPlatformOutput() bool {
	if !isWindowsService() || c.Output.Type != outputs.Console || c.Output.Output == nil {
		return false
	}
	log.Warn("running in non-interactive session with console output. " +
		"Please configure a different output type. Defaulting to null output")
	c.Output.Type, c.Output.Output = outputs.Null, &null.Config{}
	return true
}

func isWindowsService() bool {
	isWinService, err := svc.IsWindowsService()
	return err == nil && isWinService
}

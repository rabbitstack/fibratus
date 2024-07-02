/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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

package bootstrap

import (
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/util/log"
	"github.com/sirupsen/logrus"
)

// InitConfigAndLogger initializes the configuration and sets up the logger.
// We allow continuing with the initialization process even if the config file
// loading fails. In this situation, the default config flag values are used
// to tweak any of the internal behaviours.
func InitConfigAndLogger(cfg *config.Config) error {
	isLoaded := cfg.TryLoadFile(cfg.File()) == nil
	if err := cfg.Init(); err != nil {
		return err
	}
	if isLoaded {
		if err := cfg.Validate(); err != nil {
			return err
		}
	}
	if err := log.InitFromConfig(cfg.Log, "fibratus.log"); err != nil {
		return err
	}
	if !isLoaded {
		logrus.Warnf("unable to load configuration "+
			"from %s file. Falling back to default "+
			"settings...", cfg.File())
	}
	return nil
}

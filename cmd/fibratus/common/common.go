/*
 * Copyright 2020-2021 by Nedim Sabic Sabic
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

package common

import (
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/util/log"
)

// InitConfigAndLogger initializes the configuration and sets up the logger.
func InitConfigAndLogger(cfg *config.Config) error {
	if err := cfg.TryLoadFile(cfg.File()); err != nil {
		return err
	}
	if err := cfg.Init(); err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := log.InitFromConfig(cfg.Log); err != nil {
		return err
	}
	return nil
}

func PreAggregateFunc(rules *filter.Rules) func(kevt *kevent.Kevent) bool {
	return func(kevt *kevent.Kevent) bool {
		return rules.Fire(kevt)
	}
}

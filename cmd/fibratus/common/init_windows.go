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
	"github.com/rabbitstack/fibratus/pkg/syscall/security"
	"github.com/rabbitstack/fibratus/pkg/util/log"
)

// Init initializes and validates the configuration
// as given by the commands. This function will also set up
// the logger and adjust the process token with the debug
// privilege if required.
func Init(c *config.Config, debugPrivilege bool) error {
	if err := c.TryLoadFile(c.File()); err != nil {
		return err
	}
	// initialize and validate the config
	if err := c.Init(); err != nil {
		return err
	}
	if err := c.Validate(); err != nil {
		return err
	}
	// inject the debug privilege if enabled
	if c.DebugPrivilege && debugPrivilege {
		security.SetDebugPrivilege()
	}
	if err := log.InitFromConfig(c.Log); err != nil {
		return err
	}
	return nil
}

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

import "path/filepath"

type platformConfig struct{}

func newPlatformConfig() platformConfig { return platformConfig{} }

func (c *Config) addPlatformFlags() {
	c.EventSource.AddFlags(c.flags)
}

func (c *Config) initPlatform() {}

func (c *Config) Validate() error { return c.validateConfig() }

func defaultConfigFile() string { return filepath.Join("/etc", "fibratus", "fibratus.yml") }
func defaultFilamentPath() string {
	return filepath.Join("/usr", "share", "fibratus", "filaments")
}
func defaultRulesPaths() []string {
	return []string{filepath.Join("/etc", "fibratus", "rules", "*")}
}
func defaultMacrosPaths() []string {
	return []string{filepath.Join("/etc", "fibratus", "rules", "macros", "*")}
}

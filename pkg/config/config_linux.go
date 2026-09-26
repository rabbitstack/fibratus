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

import (
	"path/filepath"
)

var (
	// configFilePath defines the default value for the configuration file path
	configFilePath = filepath.Join("/etc", "fibratus", "fibratus.yml")

	// filamentsPaths defines the default directory containing filament scripts
	filamentsPaths = filepath.Join("/usr", "share", "fibratus", "filaments")

	// rulesPaths defines default rule paths
	rulesPaths = []string{filepath.Join("/etc", "fibratus", "rules", "*")}

	// macrosPaths defines default macro paths
	macrosPaths = []string{filepath.Join("/etc", "fibratus", "rules", "macros", "*")}

	// apiTransport apiTransport defines the default transport protocol for
	// the API server. It keeps the API off the network unless someone asks
	// for it. Filesystem permissions on the socket then decide who can reach it.
	apiTransport = "unix:///var/run/fibratus.sock"
)

// Config exposes the platform configuration options.
type Config struct {
	*BaseConfig
}

// NewWithOpts builds a new platform configuration store.
func NewWithOpts(options ...Option) *Config {
	c := &Config{
		BaseConfig: newWithOpts(options...),
	}
	return c
}

// Init initializes the config state.
func (c *Config) Init() error {
	return c.BaseConfig.init()
}

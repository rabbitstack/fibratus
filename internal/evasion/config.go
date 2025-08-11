/*
 * Copyright 2021-present by Nedim Sabic Sabic
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

package evasion

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	enabled             = "evasion.enabled"
	enableDirectSyscall = "evasion.enable-direct-syscall"
)

// Config contains the settings that influence the behaviour of the evasion scanner.
type Config struct {
	// Enabled indicates if evasion detections are enabled global-wise.
	Enabled bool `json:"enabled" yaml:"enabled"`
	// EnableDirectSyscall indicates if direct syscall evasion detection is enabled.
	EnableDirectSyscall bool `json:"enable-direct-syscall" yaml:"enable-direct-syscall"`
}

// InitFromViper initializes evasion config from Viper.
func (c *Config) InitFromViper(v *viper.Viper) {
	c.Enabled = v.GetBool(enabled)
	c.EnableDirectSyscall = v.GetBool(enableDirectSyscall)
}

// AddFlags adds evasion config flags to the set.
func AddFlags(flags *pflag.FlagSet) {
	flags.Bool(enabled, true, "Indicates if evasion detections are enabled global-wise")
	flags.Bool(enableDirectSyscall, true, "Indicates if direct syscall evasion detection is enabled")
}

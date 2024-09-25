/*
 * Copyright 2019-2024 by Nedim Sabic Sabic and Contributors
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

package eventlog

import (
	"github.com/spf13/pflag"
)

const (
	enabled = "alertsenders.eventlog.enabled"
	verbose = "alertsenders.eventlog.verbose"
)

// Config defines the configuration for the eventlog sender.
type Config struct {
	// Enabled indicates if the eventlog sender is enabled.
	Enabled bool `mapstructure:"enabled"`
	// Verbose activates verbose mode. In verbose mode, the full
	// event context, including parameters and the process
	// state are included in the log message.
	Verbose bool `mapstructure:"verbose"`
}

// AddFlags registers persistent flags.
func AddFlags(flags *pflag.FlagSet) {
	flags.Bool(enabled, true, "Indicates if eventlog alert sender is enabled")
	flags.Bool(verbose, false, "Enables/disables the verbose mode. In verbose mode, the full event context, including all parameters and the process information are included in the log message")
}

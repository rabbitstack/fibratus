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

package systray

import "github.com/spf13/pflag"

const (
	enabled   = "alertsenders.systray.enabled"
	sound     = "alertsenders.systray.sound"
	quietMode = "alertsenders.systray.quiet-mode"
)

// Config contains the configuration for the systray alert sender.
type Config struct {
	// Enabled indicates whether systray alert sender is enabled.
	Enabled bool `mapstructure:"enabled"`
	// Sound indicates if the associated sound is played
	// when the balloon notification is shown.
	Sound bool `mapstructure:"sound"`
	// QuietMode instructs not to display the balloon notification
	// if the current user is in quiet time.
	QuietMode bool `mapstructure:"quiet"`
}

// AddFlags registers persistent flags.
func AddFlags(flags *pflag.FlagSet) {
	flags.Bool(enabled, true, "Determines whether systray alert sender is enabled")
	flags.Bool(sound, true, "Indicates if the associated sound is played when the balloon notification is shown")
	flags.Bool(quietMode, false, "Instructs not to display the balloon notification if the current user is in quiet time")
}

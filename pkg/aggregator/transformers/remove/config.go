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

package remove

import "github.com/spf13/pflag"

const (
	pars    = "transformers.remove.params"
	enabled = "transformers.remove.enabled"
)

// Config stores the configuration for the remove transformer.
type Config struct {
	// Params is the list of parameters that are dropped from the event.
	Params []string `mapstructure:"params"`
	// Enabled indicates whether this transformer is enabled
	Enabled bool `mapstructure:"enabled"`
}

// AddFlags registers persistent flags.
func AddFlags(flags *pflag.FlagSet) {
	flags.StringSlice(pars, []string{}, "A list of comma-separated parameters that will be removed from the event")
	flags.Bool(enabled, false, "Indicates if remove transformer is enabled")
}

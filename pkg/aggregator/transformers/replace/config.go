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

package replace

import "github.com/spf13/pflag"

const (
	enabled = "transformers.replace.enabled"
)

// Config stores the configuration for the replace transformer
type Config struct {
	// Replacements describes a list of replacements that are applied on the Param.
	Replacements []Replacement `mapstructure:"replacements"`
	// Enabled indicates whether this transformer is enabled
	Enabled bool `mapstructure:"enabled"`
}

// Replacement defines the string replacement config for a specific Param.
type Replacement struct {
	Param string `mapstructure:"param"`
	Old   string `mapstructure:"old"`
	New   string `mapstructure:"new"`
}

// AddFlags registers persistent flags.
func AddFlags(flags *pflag.FlagSet) {
	flags.Bool(enabled, false, "Indicates if the replace transformer is enabled")
}

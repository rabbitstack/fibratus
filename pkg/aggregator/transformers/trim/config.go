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

package trim

import "github.com/spf13/pflag"

const (
	enabled = "transformers.trim.enabled"
)

// Trim defines the trim configuration for a single event parameter.
type Trim struct {
	Name string `mapstructure:"kparam"`
	Trim string `mapstructure:"trim"`
}

// Config stores the configuration for the trim transformer.
type Config struct {
	// Prefixes contains the mapping between distinct kparam names and the prefixes that will get trimmed from their values.
	Prefixes []Trim `mapstructure:"prefixes"`
	// Suffixes contains the mapping between distinct kparam names and the suffixes that will get trimmed from their values.
	Suffixes []Trim `mapstructure:"suffixes"`
	// Enabled determines whether trim transformer is enabled or disabled.
	Enabled bool `mapstructure:"enabled"`
}

// AddFlags registers persistent flags.
func AddFlags(flags *pflag.FlagSet) {
	flags.Bool(enabled, false, "Indicates if the trim transformer is enabled")
}

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

package rename

import "github.com/spf13/pflag"

const (
	enabled = "transformers.rename.enabled"
)

// Rename describes the configuration for the old/new parameter name.
type Rename struct {
	Old string `mapstructure:"old"`
	New string `mapstructure:"new"`
}

// Config stores the configuration of the rename transformer.
type Config struct {
	// Kparams is the list of parameters that will be renamed.
	Kparams []Rename
	// Enabled indicates whether this transformer is enabled.
	Enabled bool
}

// AddFlags registers persistent flags.
func AddFlags(flags *pflag.FlagSet) {
	flags.Bool(enabled, false, "Indicates if the rename transformer is enabled")
}

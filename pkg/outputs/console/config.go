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

package console

import "github.com/spf13/pflag"

const (
	frmt             = "output.console.format"
	tmpl             = "output.console.template"
	paramKVDelimiter = "output.console.kv-delimiter"
	enabled          = "output.console.enabled"
)

// Config contains the tweaks that influence the behaviour of the console output.
type Config struct {
	Format           string `mapstructure:"format"`
	Template         string `mapstructure:"template"`
	ParamKVDelimiter string `mapstructure:"kv-delimiter"`
	Enabled          bool   `mapstructure:"enabled"`
}

// AddFlags registers persistent flags.
func AddFlags(flags *pflag.FlagSet) {
	flags.String(frmt, string(pretty), "Specifies the output format. Choose between pretty|json")
	flags.String(paramKVDelimiter, "", "The delimiter symbol for the kparams key/value pairs")
	flags.String(tmpl, "", "Event formatting template")
	flags.Bool(enabled, true, "Indicates if the console output is enabled")
}

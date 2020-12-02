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

package tags

import (
	"github.com/spf13/pflag"
)

const (
	enabled = "transformers.tags.enabled"
)

// Tag represents a distinct tag with its key and value attached.
type Tag struct {
	Key   string `mapstructure:"key"`
	Value string `mapstructure:"value"`
}

// Config stores the configuration for the tags transformer
type Config struct {
	// Tags is the sequence of key/value pairs that are added to the event
	Tags []Tag `mapstructure:"tags"`
	// Enabled indicates whether this transformer is enabled
	Enabled bool `mapstructure:"enabled"`
}

// AddFlags registers persistent flags.
func AddFlags(flags *pflag.FlagSet) {
	flags.Bool(enabled, false, "Indicates if the tags transformer is enabled")
}

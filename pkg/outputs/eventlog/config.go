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

package eventlog

import (
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"text/template"

	"github.com/spf13/pflag"
)

const (
	enabled    = "output.eventlog.enabled"
	level      = "output.eventlog.level"
	remoteHost = "output.eventlog.remote-host"
	tmpl       = "output.eventlog.template"
)

// Config contains configuration properties for fine-tuning the eventlog output.
type Config struct {
	// Enabled determines whether the eventlog output is enabled.
	Enabled bool `mapstructure:"enabled"`
	// Level specifies the eventlog log level.
	Level string `mapstructure:"level"`
	// RemoteHost is the address of the remote eventlog intake.
	RemoteHost string `mapstructure:"remote-host"`
	// Template specifies the Go template for rendering the eventlog message.
	Template string `mapstructure:"template"`
}

func (c Config) parseTemplate() (*template.Template, error) {
	if c.Template == "" {
		// use built-in template
		return template.New("evtlog").Parse(kevent.Template)
	}
	return template.New("evtlog").Parse(c.Template)
}

// AddFlags registers persistent flags.
func AddFlags(flags *pflag.FlagSet) {
	flags.String(tmpl, "", "Go template for rendering the eventlog message")
	flags.String(level, "info", "Specifies the eventlog level")
	flags.String(remoteHost, "", "Address of the remote eventlog intake")
	flags.Bool(enabled, false, "Indicates if the eventlog output is enabled")
}

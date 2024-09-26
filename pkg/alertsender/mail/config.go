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

package mail

import "github.com/spf13/pflag"

const (
	host        = "alertsenders.mail.host"
	port        = "alertsenders.mail.port"
	user        = "alertsenders.mail.user"
	pass        = "alertsenders.mail.password"
	from        = "alertsenders.mail.from"
	to          = "alertsenders.mail.to"
	enabled     = "alertsenders.mail.enabled"
	contentType = "alertsenders.mail.content-type"
	useTemplate = "alertsenders.mail.use-template"
)

// Config contains the configuration for the mail alert sender.
type Config struct {
	// Host is the host of the SMTP server.
	Host string `mapstructure:"host"`
	// Port is the port of the SMTP server.
	Port int `mapstructure:"port"`
	// User specifies the username when authenticating to the SMTP server.
	User string `mapstructure:"user"`
	// Pass specifies the password when authenticating to the SMTP server.
	Pass string `mapstructure:"password"`
	// From specifies the sender address.
	From string `mapstructure:"from"`
	// To specifies recipients that receive the alert.
	To []string `mapstructure:"to"`
	// Enabled indicates whether mail alert sender is enabled.
	Enabled bool `mapstructure:"enabled"`
	// ContentType represents the email body content type.
	ContentType string `mapstructure:"content-type"`
	// UseTemplate indicates if the alert is rendered with HTML template.
	// If set to false, the plain text email is sent instead.
	UseTemplate bool `mapstructure:"use-template"`
}

// AddFlags registers persistent flags.
func AddFlags(flags *pflag.FlagSet) {
	flags.String(host, "", "Represents the host of the SMTP server")
	flags.Int(port, 25, "Represents the port of the SMTP server")
	flags.String(user, "", "Specifies the user name when authenticating to the SMTP server")
	flags.String(pass, "", "Specifies the password when authenticating to the SMTP server")
	flags.String(from, "", "Specifies the sender's address")
	flags.StringSlice(to, []string{}, "Specifies all the recipients that'll receive the alert")
	flags.Bool(enabled, false, "Indicates whether mail alert sender is enabled")
	flags.String(contentType, "text/html", "Represents the email body content type")
	flags.Bool(useTemplate, true, "Indicates if the alert is rendered with HTML template")
}

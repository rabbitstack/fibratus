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

package http

import (
	"time"

	"github.com/spf13/pflag"

	"github.com/rabbitstack/fibratus/pkg/outputs"
)

const (
	httpEnabled       = "output.http.enabled"
	httpTimeout       = "output.http.timeout"
	httpProxyURL      = "output.http.proxy-url"
	httpProxyUsername = "output.http.proxy-username"
	httpProxyPassword = "output.http.proxy-password"
	httpMethod        = "output.http.method"
	httpUsername      = "output.http.username"
	httpPassword      = "output.http.password"
	httpEndpoints     = "output.http.endpoints"
	httpEnableGzip    = "output.http.enable-gzip"
)

// Config contains the options for tweaking the HTTP output behaviour.
type Config struct {
	outputs.TLSConfig
	// Enabled determines whether HTTP output is enabled.
	Enabled bool `mapstructure:"enabled"`
	// Endpoints contains a collection of URLs to which the events are sent.
	Endpoints []string `mapstructure:"endpoints"`
	// Timeout represents the timeout for the HTTP requests.
	Timeout time.Duration `mapstructure:"timeout"`
	// ProxyURL specifies the HTTP proxy URL.
	ProxyURL string `mapstructure:"proxy-url"`
	// ProxyUsername is the username for proxy authentication.
	ProxyUsername string `mapstructure:"proxy-username"`
	// ProxyPassword is the password for proxy authetnication.
	ProxyPassword string `mapstructure:"proxy-password"`
	// Method determines the HTTP verb in the requests.
	Method string `mapstructure:"method"`
	// Username is the username for the basic HTTP authentication.
	Username string `mapstructure:"username"`
	// Password is the password for the basic HTTP authentication.
	Password string `mapstructure:"password"`
	// Headers contains a list of additional headers in the HTTP request
	Headers map[string]string `mapstructure:"headers"`
	// EnableGzip specifies whether the gzip compression is enabled.
	EnableGzip bool `mapstructure:"enable-gzip"`
}

// AddFlags registers persistent flags for the HTTP output.
func AddFlags(flags *pflag.FlagSet) {
	flags.Bool(httpEnabled, false, "Determines whether the HTTP output is enabled")
	flags.Duration(httpTimeout, time.Second*5, "Represents the timeout for the HTTP requests")
	flags.StringSlice(httpEndpoints, []string{}, "Endpoints to which the events are sent. Must contain the HTTP/S protocol schema")
	outputs.AddTLSFlags(flags, outputs.HTTP)
}

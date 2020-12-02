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

package config

import (
	"github.com/spf13/viper"
	"time"
)

const (
	transport = "api.transport"
	timeout   = "api.timeout"
)

// Config contains API specific config options.
type APIConfig struct {
	// Transport specifies the underlying transport protocol for the API HTTP server.
	Transport string `json:"api.transport" yaml:"api.transport"`
	// Timeout determines the timeout for the API server responses
	Timeout time.Duration `json:"api.timeout" yaml:"api.timeout"`
}

// initFromViper initializes API configuration from Viper.
func (c *APIConfig) initFromViper(v *viper.Viper) {
	c.Transport = v.GetString(transport)
	c.Timeout = v.GetDuration(timeout)
}

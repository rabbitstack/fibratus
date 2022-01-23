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

	"github.com/rabbitstack/fibratus/pkg/outputs"
)

// Config contains the options for tweaking the HTTP output behaviour.
type Config struct {
	outputs.TLSConfig
	// Enabled determines whether HTTP output is enabled.
	Enabled bool `mapstructure:"enabled"`
	// Endpoints contains a collection of URLs to which the events are sent. Internal
	// load balancer spreads the requests across available endpoints.
	Endpoints []string `mapstructure:"endpoints"`
	// Timeout represents the timeout for HTTP requests
	Timeout time.Duration
}

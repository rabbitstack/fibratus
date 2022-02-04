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
	"fmt"
	"net/http"
	"net/url"

	"github.com/rabbitstack/fibratus/pkg/util/tls"
)

// newHTTPClient builds a fresh stdlib HTTP client. The HTTP proxy and TLS config is set
// accordingly if enabled in the HTTP output preferences.
func newHTTPClient(config Config) (*http.Client, error) {
	tlsConfig, err := tls.MakeConfig(config.TLSCert, config.TLSKey, config.TLSCA, config.TLSInsecureSkipVerify)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS config: %v", err)
	}

	proxy := http.ProxyFromEnvironment
	if config.ProxyURL != "" {
		address, err := url.Parse(config.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid HTTP proxy url %q: %w", config.ProxyURL, err)
		}
		if config.ProxyUsername != "" && config.ProxyPassword != "" {
			proxy = http.ProxyURL(&url.URL{
				Scheme: address.Scheme,
				User:   url.UserPassword(config.ProxyUsername, config.ProxyPassword),
				Host:   config.ProxyURL,
			})
		} else {
			proxy = http.ProxyURL(address)
		}
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		Proxy:           proxy,
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}

	return httpClient, nil
}

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

package rest

import (
	"context"
	"errors"
	"github.com/rabbitstack/fibratus/pkg/api"
	"io"
	"net"
	"net/http"
	"path"
	"strings"
	"time"
)

var transport *http.Transport

type opts struct {
	addr        string
	uri         string
	contentType string
	timeout     time.Duration
}

// Option represents the option for the HTTP client.
type Option func(o *opts)

// WithTransport sets the preferred transport for the HTTP client.
func WithTransport(addr string) Option {
	return func(o *opts) {
		o.addr = addr
		if strings.HasPrefix(addr, `npipe:///`) {
			transport = &http.Transport{
				DialContext: api.DialPipe(addr),
			}
		} else {
			transport = &http.Transport{
				DialContext: (&net.Dialer{}).DialContext,
			}
		}
	}
}

// WithURI initializes the URI where the request is sent.
func WithURI(uri string) Option {
	return func(o *opts) {
		o.uri = uri
	}
}

// WithContentType sets the content type header for the HTTP requests.
func WithContentType(contentType string) Option {
	return func(o *opts) {
		o.contentType = contentType
	}
}

// Get performs the GET request.
func Get(opts ...Option) ([]byte, error) {
	return request("GET", opts...)
}

func request(method string, options ...Option) ([]byte, error) {
	var opts opts
	for _, opt := range options {
		opt(&opts)
	}

	if transport == nil {
		return nil, errors.New("transport is not initialized")
	}

	timeout := opts.timeout
	if timeout == 0 {
		timeout = time.Second * 10
	}

	contentType := opts.contentType
	if contentType == "" {
		contentType = "application/json"
	}

	client := http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	scheme := "http://"
	addr := strings.TrimPrefix(opts.addr, `npipe:///`)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, scheme+path.Join(addr, opts.uri), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", contentType)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

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
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io/ioutil"
	libhttp "net/http"
	"net/url"

	"github.com/rabbitstack/fibratus/pkg/util/version"

	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/outputs"
)

// userAgentHeader represents the value of the User-Agent header
var userAgentHeader = version.ProductToken()

// defaultContentType represents the default content type
const defaultContentType = "application/json"

type http struct {
	client *libhttp.Client
	config Config
	url    string
}

func init() {
	outputs.Register(outputs.HTTP, initHTTP)
}

func initHTTP(config outputs.Config) (outputs.OutputGroup, error) {
	cfg, ok := config.Output.(Config)
	if !ok {
		return outputs.Fail(outputs.ErrInvalidConfig(outputs.HTTP, config.Output))
	}

	clients := make([]outputs.Client, len(cfg.Endpoints))
	for i, endpoint := range cfg.Endpoints {
		_, err := url.Parse(endpoint)
		if err != nil {
			return outputs.Fail(err)
		}
		client, err := newHTTPClient(cfg)
		if err != nil {
			return outputs.Fail(err)
		}

		http := &http{
			client: client,
			config: cfg,
			url:    endpoint,
		}

		clients[i] = http
	}

	return outputs.Success(clients...), nil
}

func (h *http) Connect() error { return nil }
func (h *http) Close() error   { return nil }

func (h *http) Publish(batch *kevent.Batch) error {
	defer batch.Release()
	buf, err := h.prepareBody(batch.MarshalJSON())
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), h.config.Timeout)
	defer cancel()
	req, err := libhttp.NewRequestWithContext(ctx, h.config.Method, h.url, bytes.NewBuffer(buf))
	if err != nil {
		return err
	}

	h.setHeaders(req)
	h.setBasicAuth(req)

	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf("http request failed with %d status code: %v", resp.StatusCode, string(body))
	}

	return nil
}

// setBasicAuth sets the request's Authorization header to use HTTP
// Basic Authentication with the provided username and password.
func (h *http) setBasicAuth(req *libhttp.Request) {
	if h.config.Username != "" && h.config.Password != "" {
		req.SetBasicAuth(h.config.Username, h.config.Password)
	}
}

// setHeaders populates required and optional request headers.
func (h *http) setHeaders(req *libhttp.Request) {
	req.Header.Set("User-Agent", userAgentHeader)
	req.Header.Set("Content-Type", defaultContentType)
	if h.config.EnableGzip {
		req.Header.Set("Content-Encoding", "gzip")
	}
	for k, v := range h.config.Headers {
		req.Header.Set(k, v)
	}
}

// prepareBody returns the request body as produced by the serializer if
// the gzip compression is disabled. Otherwise, the body is compressed by
// gzip writer before transporting it to remote endpoints.
func (h *http) prepareBody(body []byte) ([]byte, error) {
	if !h.config.EnableGzip {
		return body, nil
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(body); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

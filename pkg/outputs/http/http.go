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
	"context"
	libhttp "net/http"
	"net/url"

	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/outputs"
)

const userAgentHeader = "fibratus"

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

func (h *http) Connect() error {
	return nil
}

func (h *http) Close() error {
	return nil
}

func (h *http) Publish(batch *kevent.Batch) error {
	body := batch.MarshalJSON()
	defer batch.Release()

	ctx, cancel := context.WithTimeout(context.Background(), h.config.Timeout)
	defer cancel()
	req, err := libhttp.NewRequestWithContext(ctx, h.config.Method, h.url, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	if h.config.Username != "" && h.config.Password != "" {
		req.SetBasicAuth(h.config.Username, h.config.Password)
	}

	req.Header.Set("User-Agent", userAgentHeader)
	//req.Header.Set("Content-Type", defaultContentType)
	//if h.ContentEncoding == "gzip" {
	//	req.Header.Set("Content-Encoding", "gzip")
	//}
	for k, v := range h.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	return nil
}

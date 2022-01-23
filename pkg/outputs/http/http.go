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
	"net/url"

	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/outputs"
)

type http struct {
	client *client
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

		http := &http{client: newHTTPClient(cfg)}

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
	return nil
}

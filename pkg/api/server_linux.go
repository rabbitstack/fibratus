//go:build linux

/*
 * Copyright 2026 by Mostafa Moradian
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

package api

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/config"
)

var listener net.Listener

// StartServer starts the HTTP server with the specified configuration.
func StartServer(c *config.Config) error {
	var err error
	transport := c.API.Transport
	if strings.HasPrefix(transport, "unix://") {
		path := strings.TrimPrefix(transport, "unix://")
		_ = os.Remove(path)
		listener, err = net.Listen("unix", path)
		if err != nil {
			return fmt.Errorf("fail to listen on the %q socket: %w", path, err)
		}
	} else {
		listener, err = net.Listen("tcp", transport)
		if err != nil {
			return fmt.Errorf("fail to listen on %q: %w", transport, err)
		}
	}

	setupServer(listener, c)
	return nil
}

// CloseServer shutdowns the server by stopping the listener.
func CloseServer() error {
	if listener != nil {
		return listener.Close()
	}
	return nil
}

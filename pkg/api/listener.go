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

package api

import (
	"context"
	"fmt"
	"github.com/Microsoft/go-winio"
	"net"
	"strings"
)

// MakePipeListener produces a new listener for receiving requests over a named pipe.
func MakePipeListener(pipePath, descriptor string) (net.Listener, error) {
	npipe := transformPipePath(pipePath)
	l, err := winio.ListenPipe(npipe, &winio.PipeConfig{SecurityDescriptor: descriptor})
	if err != nil {
		return nil, fmt.Errorf("fail to listen on the %q pipe: %v", pipePath, err)
	}
	return l, nil
}

// makeTCPListener produces a new listener for receiving requests over TCP.
func makeTCPListener(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}

// DialPipe creates a dialer to be used with the http.Client to connect to a named pipe.
func DialPipe(pipePath string) func(context.Context, string, string) (net.Conn, error) {
	npipe := transformPipePath(pipePath)
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		return winio.DialPipeContext(ctx, npipe)
	}
}

// transformPipePath takes an input type name defined as a URI like `npipe:///hello` and transform it into
// `\\.\pipe\hello`. Borrowed from https://github.com/elastic/beats/blob/master/libbeat/api/npipe/listener_windows.go
func transformPipePath(name string) string {
	if strings.HasPrefix(name, "npipe:///") {
		path := strings.TrimPrefix(name, "npipe:///")
		return `\\.\pipe\` + path
	}

	if strings.HasPrefix(name, `\\.\pipe\`) {
		return name
	}

	return name
}

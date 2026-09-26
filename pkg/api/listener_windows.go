//go:build windows

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
	"fmt"
	"net"
	"os/user"
	"strings"

	"github.com/Microsoft/go-winio"
)

// MakeListener builds a new listener that either accepts traffic over named pipe or TCP socket.
func MakeListener(transport string) (net.Listener, error) {
	if strings.HasPrefix(transport, `npipe:///`) {
		usr, err := user.Current()
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve the current user: %v", err)
		}
		// Named pipe security and access rights.
		// We create the pipe and the specific users should only be able to write to it.
		// See docs: https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
		// String definition: https://docs.microsoft.com/en-us/windows/win32/secauthz/ace-strings
		// Give generic read/write access to the specified user.
		descriptor := "D:P(A;;GA;;;" + usr.Uid + ")"
		return makePipeListener(transport, descriptor)
	}
	return MakeTCPListener(transport)
}

// makePipeListener produces a new listener for receiving requests over a named pipe.
func makePipeListener(pipePath, descriptor string) (net.Listener, error) {
	npipe := transformPipePath(pipePath)
	l, err := winio.ListenPipe(npipe, &winio.PipeConfig{SecurityDescriptor: descriptor})
	if err != nil {
		return nil, fmt.Errorf("fail to listen on the %q pipe: %v", pipePath, err)
	}
	return l, nil
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

//go:build linux

/*
 * Copyright 2026 by Mostafa Moradian
 * Copyright 2026 by Nedim Sabic Sabic
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
)

// MakeListener builds a new listener that either accepts traffic over UNIX domain socket or TCP.
func MakeListener(transport string) (net.Listener, error) {
	if strings.HasPrefix(transport, "unix://") {
		path := strings.TrimPrefix(transport, "unix://")
		return makeUNIXSocketListener(path)
	}
	return MakeTCPListener(transport)
}

// makeUNIXSocketListener produces a new listener for receiving requests over a UNIX domain socket.
func makeUNIXSocketListener(path string) (net.Listener, error) {
	// remove any stale socket file left behind by a previous run.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to remove stale socket %q: %v", path, err)
	}

	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("fail to listen on the %q socket: %v", path, err)
	}

	// restrict the socket to the owning user only, mirroring the
	// single-user access granted to the named pipe on Windows.
	if err := os.Chmod(path, 0600); err != nil {
		l.Close()
		return nil, fmt.Errorf("failed to set permissions on the %q socket: %v", path, err)
	}

	return l, nil
}

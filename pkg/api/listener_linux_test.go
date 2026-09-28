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
	"context"
	"net"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDialLocalTransport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fibratus.sock")
	listener, err := net.Listen("unix", path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, listener.Close()) })

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	conn, err := DialLocalTransport("unix://"+path)(context.Background(), "", "")
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	require.NoError(t, (<-accepted).Close())
}

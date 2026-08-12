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

package rest

import (
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetUnixSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fibratus.sock")
	listener, err := net.Listen("unix", path)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/config", func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte("test")); err != nil {
			t.Fatal(err)
		}
	})

	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = listener
	srv.Start()
	defer srv.Close()

	resp, err := Get(WithURI("config"), WithTransport("unix://"+path))
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "test", string(resp))
}

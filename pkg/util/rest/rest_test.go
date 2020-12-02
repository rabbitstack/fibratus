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
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os/user"
	"strings"
	"testing"
)

func TestGet(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("test"))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := Get(WithURI("config"), WithTransport(fmt.Sprintf("localhost:%s", port(srv.URL))))
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "test", string(resp))
}

func TestGetPipe(t *testing.T) {
	usr, err := user.Current()
	require.NoError(t, err)
	descriptor := "D:P(A;;GA;;;" + usr.Uid + ")"
	listener, err := api.MakePipeListener(`npipe:///fibratus`, descriptor)
	require.NoError(t, err)

	mux := http.NewServeMux()

	mux.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("test"))
	})

	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = listener

	srv.Start()
	defer srv.Close()

	resp, err := Get(WithURI("config"), WithTransport(`npipe:///fibratus`))
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "test", string(resp))
}

func port(s string) string {
	i := strings.LastIndex(s, ":")
	if i == 0 {
		return ""
	}
	return s[i+1:]
}

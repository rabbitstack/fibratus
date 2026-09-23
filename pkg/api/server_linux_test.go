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

// Package api_test lives outside the package because the REST client imports
// the API for its local transport dialer.
package api_test

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/rabbitstack/fibratus/pkg/api"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/util/rest"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The config endpoint renders through viper, so the config has to come from
// the normal construction path rather than a bare struct.
func newConfig(t *testing.T, transport string) *config.Config {
	t.Helper()
	c := config.NewWithOpts(config.WithRun())
	c.MustViperize(&cobra.Command{})
	require.NoError(t, c.Init())
	c.API.Transport = transport
	return c
}

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	return addr
}

// The endpoints behind fibratus config and fibratus stats have to answer over
// both transports, since a socket is the default and a TCP address is what an
// operator switches to for remote access.
func TestServerServesBothTransports(t *testing.T) {
	for _, transport := range []string{
		"unix://" + filepath.Join(t.TempDir(), "fibratus.sock"),
		freeTCPAddr(t),
	} {
		t.Run(transport, func(t *testing.T) {
			cfg := newConfig(t, transport)
			require.NoError(t, api.StartServer(cfg))
			t.Cleanup(func() { require.NoError(t, api.CloseServer()) })

			body, err := rest.Get(rest.WithTransport(transport), rest.WithURI("debug/vars"))
			require.NoError(t, err)
			var vars map[string]any
			require.NoError(t, json.Unmarshal(body, &vars))
			assert.Contains(t, vars, "cmdline", "expvar payload is what fibratus stats reads")

			// This endpoint renders the config as text, which is what
			// fibratus config prints verbatim.
			body, err = rest.Get(rest.WithTransport(transport), rest.WithURI("config"))
			require.NoError(t, err)
			for _, section := range []string{"aggregator", "api", "eventsource", "filters", "output"} {
				assert.Contains(t, string(body), section)
			}
		})
	}
}

// A socket left behind by a killed process must not keep the server from
// starting, otherwise an unclean shutdown needs manual cleanup before restart.
func TestServerReplacesStaleSocket(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "fibratus.sock")
	require.NoError(t, os.WriteFile(socket, nil, 0o600))

	cfg := newConfig(t, "unix://"+socket)
	require.NoError(t, api.StartServer(cfg))
	t.Cleanup(func() { require.NoError(t, api.CloseServer()) })

	body, err := rest.Get(rest.WithTransport("unix://"+socket), rest.WithURI("debug/vars"))
	require.NoError(t, err)
	assert.NotEmpty(t, body)
}

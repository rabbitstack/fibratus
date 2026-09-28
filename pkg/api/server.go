/*
 * Copyright 2020-2026 by Nedim Sabic Sabic
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
	"errors"
	"expvar"
	"net"
	"net/http"
	"net/http/pprof"
	"runtime/debug"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/api/handler"
	"github.com/rabbitstack/fibratus/pkg/config"
	log "github.com/sirupsen/logrus"
)

// Server wraps http.Server and owns the router lifecycle.
type Server struct {
	http *http.Server
	lis  net.Listener
}

// NewServer builds a Server bound to the given listener, wired
// with the config, debug/vars and pprof endpoints.
func NewServer(c *config.Config) (*Server, error) {
	mux := http.NewServeMux()
	mux.Handle("/config", handler.Config(c))
	mux.Handle("/debug/vars", expvar.Handler())

	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/freemem", func(w http.ResponseWriter, r *http.Request) {
		debug.FreeOSMemory()
	})

	lis, err := MakeListener(c.API.Transport)
	if err != nil {
		return nil, err
	}

	return &Server{
		lis:  lis,
		http: &http.Server{Handler: mux},
	}, nil
}

// Start begins serving in the background. It does not block.
func (s *Server) Start() {
	go func() {
		if err := s.http.Serve(s.lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			log.Errorf("unable to bind the API server: %v", err)
		}
	}()
}

// Stop gracefully shuts down the server.
func (s *Server) Stop(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

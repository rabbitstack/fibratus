/*
 * Copyright 2020-2021 by Nedim Sabic Sabic
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

func setupAndListen(lis net.Listener, c *config.Config) {
	mux := http.NewServeMux()
	mux.Handle("/config", handler.Config(c))
	mux.Handle("/debug/vars", expvar.Handler())

	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/freemem", func(writer http.ResponseWriter, request *http.Request) {
		debug.FreeOSMemory()
	})

	srv := &http.Server{
		Handler: mux,
	}

	go func() {
		if err := srv.Serve(lis); err != nil && err != http.ErrServerClosed {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			log.Errorf("unable to bind the API server: %v", err)
		}
	}()
}

// CloseServer shutdowns the server by stopping the listener.
func CloseServer() error {
	if listener != nil {
		return listener.Close()
	}
	return nil
}

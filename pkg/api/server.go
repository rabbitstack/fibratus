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
	"expvar"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/api/handler"
	"github.com/rabbitstack/fibratus/pkg/config"
	log "github.com/sirupsen/logrus"
	"net"
	"net/http"
	"net/http/pprof"
	"os/user"
	"runtime/debug"
	"strings"
	// register expvar stats
	_ "expvar"
	// register pprof handlers
	_ "net/http/pprof"
)

var listener net.Listener

// StartServer starts the HTTP server with the specified configuration.
func StartServer(c *config.Config) error {
	var err error
	apiConfig := c.API
	if strings.HasPrefix(apiConfig.Transport, `npipe:///`) {
		usr, err := user.Current()
		if err != nil {
			return fmt.Errorf("failed to retrieve the current user: %v", err)
		}
		// Named pipe security and access rights.
		// We create the pipe and the specific users should only be able to write to it.
		// See docs: https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
		// String definition: https://docs.microsoft.com/en-us/windows/win32/secauthz/ace-strings
		// Give generic read/write access to the specified user.
		descriptor := "D:P(A;;GA;;;" + usr.Uid + ")"
		listener, err = MakePipeListener(apiConfig.Transport, descriptor)
		if err != nil {
			return err
		}
	} else {
		listener, err = makeTCPListener(apiConfig.Transport)
	}
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle("/config", handler.Config(c))
	mux.Handle("/debug/vars", expvar.Handler())

	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/freemem", func(writer http.ResponseWriter, request *http.Request) {
		debug.FreeOSMemory()
	})

	srv := &http.Server{
		//WriteTimeout: apiConfig.Timeout,
		Handler: mux,
	}

	go func() {
		if err := srv.Serve(listener); err != nil {
			log.Errorf("unable to bind the API server: %v", err)
		}
	}()

	return nil
}

// CloseServer shutdowns the server by stopping the listener.
func CloseServer() error {
	if listener != nil {
		return listener.Close()
	}
	return nil
}

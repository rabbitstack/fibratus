/*
 * Copyright 2019-2026 by Nedim Sabic Sabic
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

	"github.com/Microsoft/go-winio"
)

// DialLocalTransport creates a dialer to be used with the http.Client to connect to a named pipe.
func DialLocalTransport(path string) func(context.Context, string, string) (net.Conn, error) {
	npipe := transformPipePath(path)
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		return winio.DialPipeContext(ctx, npipe)
	}
}

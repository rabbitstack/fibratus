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

package interceptors

import "github.com/rabbitstack/fibratus/pkg/kevent"

// InterceptorType is an alias for the interceptor type
type InterceptorType uint8

const (
	// Ps represents the process interceptor.
	Ps InterceptorType = iota
	// Fs represents the file system interceptor.
	Fs
	// Registry represents the registry interceptor.
	Registry
	// Image represents the image interceptor.
	Image
	// Net represents the network interceptor.
	Net
	// Handle represents the handle interceptor.
	Handle
)

// KstreamInterceptor is the minimal interface that each kernel stream interceptor has to satisfy. Kernel stream interceptor
// has the ability to augment kernel event with additional parameters. It is also capable of building a state machine
// from the flow of kernel events going through it. The interceptor can also decide to drop the inbound kernel event by
// returning an error via its `Intercept` method.
type KstreamInterceptor interface {
	// Intercept receives an existing kernel event possibly mutating its state. The event is filtered out if
	// this method returns an error. If it returns true, the next interceptor in the chain is evaluated.
	Intercept(kevt *kevent.Kevent) (*kevent.Kevent, bool, error)

	// Name returns a human-readable name of this interceptor.
	Name() InterceptorType
}

// String returns a human-friendly interceptor name.
func (typ InterceptorType) String() string {
	switch typ {
	case Ps:
		return "process"
	case Fs:
		return "file"
	case Registry:
		return "registry"
	case Image:
		return "image"
	case Net:
		return "net"
	case Handle:
		return "handle"
	default:
		return "unknown"
	}
}

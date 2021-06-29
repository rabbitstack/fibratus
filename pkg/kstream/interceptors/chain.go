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

import (
	"expvar"
	"fmt"
	kerrors "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
)

// interceptorFailures counts the number of failures caused by interceptors while processing kernel events
var interceptorFailures = expvar.NewInt("kevent.interceptor.failures")

// Chain defines the method that all chan interceptors have to satisfy.
type Chain interface {
	// Dispatch pushes a kernel event into interceptor chain. Interceptors are applied sequentially, so we have to make
	// sure that any interceptor providing additional context to the next interceptor is defined first in the chain. If
	// one interceptor fails, the next interceptor in chain is invoked.
	Dispatch(kevt *kevent.Kevent) (*kevent.Kevent, error)
	// Close closes the interceptor chain and frees all allocated resources.
	Close() error
}

func (c *chain) addInterceptor(interceptor KstreamInterceptor) {
	if interceptor == nil {
		return
	}
	c.interceptors = append(c.interceptors, interceptor)
}

// Dispatch pushes a kernel event into interceptor chain. Interceptors are applied sequentially, so we have to make
// sure that any interceptor providing additional context to the next interceptor is defined first in the chain. If
// one interceptor fails, the next interceptor in chain is invoked.
func (c chain) Dispatch(kevt *kevent.Kevent) (*kevent.Kevent, error) {
	var errs = make([]error, 0)
	var cukerr error

	for _, interceptor := range c.interceptors {
		var err error
		var next bool
		kevt, next, err = interceptor.Intercept(kevt)
		if err != nil {
			if !kerrors.IsCancelUpstreamKevent(err) {
				interceptorFailures.Add(1)
				errs = append(errs, fmt.Errorf("%q interceptor failed with error: %v", interceptor.Name(), err))
				continue
			} else {
				cukerr = err
			}
		}
		if !next {
			break
		}
	}

	if len(errs) > 0 {
		return kevt, multierror.Wrap(errs...)
	}

	if cukerr != nil {
		return kevt, cukerr
	}

	return kevt, nil
}

// Close closes the interceptor chain and frees all allocated resources.
func (c chain) Close() error {
	for _, interceptor := range c.interceptors {
		interceptor.Close()
	}
	return nil
}

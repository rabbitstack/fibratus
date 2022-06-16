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

package interceptors

import (
	"expvar"

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/yara"
	log "github.com/sirupsen/logrus"
)

// EnqueueKeventCallback is the type definition for the event enqueue callback function
type EnqueueKeventCallback func(kevent *kevent.Kevent) error

// deferredEnqueued counts the number of deferred events
var deferredEnqueued = expvar.NewInt("kstream.deferred.kevents.enqueued")

type chain struct {
	interceptors  []KstreamInterceptor
	deferredKevts chan *kevent.Kevent
	psnapshotter  ps.Snapshotter
	cb            EnqueueKeventCallback
}

// NewChain constructs the interceptor chain. It arranges all the interceptors
// according to enabled kernel event categories.
func NewChain(
	psnap ps.Snapshotter,
	hsnap handle.Snapshotter,
	config *config.Config,
	cb EnqueueKeventCallback,
) Chain {
	var (
		chain = &chain{
			psnapshotter:  psnap,
			cb:            cb,
			interceptors:  make([]KstreamInterceptor, 0),
			deferredKevts: make(chan *kevent.Kevent, 1000),
		}
		devMapper = fs.NewDevMapper()
		scanner   yara.Scanner
	)

	if config.Yara.Enabled {
		var err error
		scanner, err = yara.NewScanner(psnap, config.Yara)
		if err != nil {
			log.Warnf("unable to start YARA scanner: %v", err)
		}
	}

	chain.addInterceptor(newPsInterceptor(psnap, scanner))

	if config.Kstream.EnableFileIOKevents {
		chain.addInterceptor(newFsInterceptor(devMapper, hsnap, config))
	}
	if config.Kstream.EnableRegistryKevents {
		chain.addInterceptor(newRegistryInterceptor(hsnap, config))
	}
	if config.Kstream.EnableImageKevents {
		chain.addInterceptor(newImageInterceptor(psnap, devMapper, scanner))
	}
	if config.Kstream.EnableNetKevents {
		chain.addInterceptor(newNetInterceptor())
	}
	if config.Kstream.EnableHandleKevents {
		chain.addInterceptor(newHandleInterceptor(hsnap, handle.NewObjectTypeStore(), devMapper, chain.deferredKevts, config))
		go chain.consumeDeferred()
	}

	return chain
}

// consumeDeferred is responsible for receiving the events
// that have been deferred by the interceptors. Events are
// usually deferred when some of their parameters or global
// state depend on the presence of other events. For example,
// CreateHandle events sometimes lack the involved handle name,
// but their counterpart, CloseHandle events contain that
// information. So, we wait for the CloseHandle counterpart to
// occur to augment the deferred event with the handle name param.
func (c *chain) consumeDeferred() {
	for kevt := range c.deferredKevts {
		if c.cb != nil {
			err := c.cb(kevt)
			if err == nil {
				deferredEnqueued.Add(1)
			}
		}
	}
}

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
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/yara"
	log "github.com/sirupsen/logrus"
)

type chain struct {
	interceptors []KstreamInterceptor
}

// NewChain constructs the interceptor chain. It arranges all the interceptors
// according to enabled kernel event categories.
func NewChain(
	psnap ps.Snapshotter,
	hsnap handle.Snapshotter,
	rundownFn func() error,
	config *config.Config,
	deferredKevtsCh chan *kevent.Kevent,
) Chain {
	var (
		chain     = &chain{interceptors: make([]KstreamInterceptor, 0)}
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
		chain.addInterceptor(newFsInterceptor(devMapper, hsnap, config, rundownFn))
	}
	if config.Kstream.EnableRegistryKevents {
		chain.addInterceptor(newRegistryInterceptor(hsnap))
	}
	if config.Kstream.EnableImageKevents {
		chain.addInterceptor(newImageInterceptor(psnap, devMapper, scanner))
	}
	if config.Kstream.EnableNetKevents {
		chain.addInterceptor(newNetInterceptor())
	}
	if config.Kstream.EnableHandleKevents {
		chain.addInterceptor(newHandleInterceptor(hsnap, handle.NewObjectTypeStore(), devMapper, deferredKevtsCh))
	}

	return chain
}

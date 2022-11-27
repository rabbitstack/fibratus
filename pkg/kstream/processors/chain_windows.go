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

package processors

import (
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/yara"
	log "github.com/sirupsen/logrus"
)

type chain struct {
	processors   []Processor
	psnapshotter ps.Snapshotter
}

// NewChain constructs the processor chain. It arranges all the processors
// according to enabled kernel event categories.
func NewChain(
	psnap ps.Snapshotter,
	hsnap handle.Snapshotter,
	config *config.Config,
) Chain {
	var (
		chain = &chain{
			psnapshotter: psnap,
			processors:   make([]Processor, 0),
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

	chain.addProcessor(newPsProcessor(psnap, scanner))

	if config.Kstream.EnableFileIOKevents {
		chain.addProcessor(newFsProcessor(hsnap))
	}
	if config.Kstream.EnableRegistryKevents {
		chain.addProcessor(newRegistryProcessor(hsnap))
	}
	if config.Kstream.EnableImageKevents {
		chain.addProcessor(newImageProcessor(psnap, scanner))
	}
	if config.Kstream.EnableNetKevents {
		chain.addProcessor(newNetProcessor())
	}
	if config.Kstream.EnableHandleKevents {
		chain.addProcessor(newHandleProcessor(hsnap, handle.NewObjectTypeStore(), devMapper))
	}
	return chain
}

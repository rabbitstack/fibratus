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

package processors

import (
	"expvar"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"sync"
	"time"
)

var imageFileCharacteristicsCacheHits = expvar.NewInt("image.file.characteristics.cache.hits")

var modTTL = time.Minute * 10

type imageProcessor struct {
	psnap  ps.Snapshotter
	mods   map[string]*imageFileCharacteristics
	mu     sync.Mutex
	purger *time.Ticker
	quit   chan struct{}
}

func newImageProcessor(psnap ps.Snapshotter) Processor {
	m := &imageProcessor{
		psnap:  psnap,
		mods:   make(map[string]*imageFileCharacteristics),
		purger: time.NewTicker(time.Minute),
		quit:   make(chan struct{}, 1),
	}

	go m.purge()

	return m
}

func (*imageProcessor) Name() ProcessorType { return Image }

func (m *imageProcessor) ProcessEvent(e *event.Event) (*event.Event, bool, error) {
	if e.IsLoadImageInternal() {
		// state management
		return e, false, m.psnap.AddModule(e)
	}

	if e.IsLoadImage() {
		// is image characteristics data cached?
		path := e.GetParamAsString(params.ImagePath)
		key := path + e.GetParamAsString(params.ImageCheckSum)

		m.mu.Lock()
		defer m.mu.Unlock()
		c, ok := m.mods[key]
		if !ok {
			// parse PE image data
			var err error
			c, err = parseImageFileCharacteristics(path)
			if err != nil {
				return e, false, m.psnap.AddModule(e)
			}
			c.keepalive()
			m.mods[key] = c
		} else {
			imageFileCharacteristicsCacheHits.Add(1)
			c.keepalive()
		}

		// append event parameters
		e.AppendParam(params.FileIsDLL, params.Bool, c.isDLL)
		e.AppendParam(params.FileIsDriver, params.Bool, c.isDriver)
		e.AppendParam(params.FileIsExecutable, params.Bool, c.isExe)
		e.AppendParam(params.FileIsDotnet, params.Bool, c.isDotnet)
	}

	if e.IsUnloadImage() {
		pid := e.Params.MustGetPid()
		addr := e.Params.TryGetAddress(params.ImageBase)
		if pid == 0 {
			pid = e.PID
		}
		return e, false, m.psnap.RemoveModule(pid, addr)
	}

	if e.IsLoadImage() || e.IsImageRundown() {
		return e, false, m.psnap.AddModule(e)
	}
	return e, true, nil
}

func (m *imageProcessor) Close() {
	m.quit <- struct{}{}
}

func (m *imageProcessor) purge() {
	for {
		select {
		case <-m.purger.C:
			m.mu.Lock()
			for key, mod := range m.mods {
				if time.Since(mod.accessed) > modTTL {
					delete(m.mods, key)
				}
			}
			m.mu.Unlock()
		case <-m.quit:
			return
		}
	}
}

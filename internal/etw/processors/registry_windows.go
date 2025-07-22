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
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/util/key"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/handle"
)

var (
	// ErrReadValue describes an error occurred while reading the registry value
	ErrReadValue = func(key, subkey string, err error) error {
		return fmt.Errorf("unable to read value %s : %v", filepath.Join(key, subkey), err)
	}

	// valueTTL specifies the maximum allowed period for RegSetValueInternal events
	// to remain in the queue
	valueTTL = time.Minute * 2
	// valuePurgerInterval specifies the purge interval for stale values
	valuePurgerInterval = time.Minute

	// kcbCount counts the total KCBs found during the duration of the kernel session
	kcbCount      = expvar.NewInt("registry.kcb.count")
	kcbMissCount  = expvar.NewInt("registry.kcb.misses")
	keyHandleHits = expvar.NewInt("registry.key.handle.hits")

	readValueOps     = expvar.NewInt("registry.read.value.ops")
	capturedDataHits = expvar.NewInt("registry.data.hits")

	handleThrottleCount uint32
)

const (
	maxHandleQueries = 200
)

type registryProcessor struct {
	// keys stores the mapping between the KCB (Key Control Block) and the key name.
	keys  map[uint64]string
	hsnap handle.Snapshotter

	values map[uint32][]*event.Event
	mu     sync.Mutex

	purger *time.Ticker

	quit chan struct{}
}

func newRegistryProcessor(hsnap handle.Snapshotter) Processor {
	// schedule a ticker that resets the throttle count every minute
	tick := time.NewTicker(time.Minute)
	go func() {
		for {
			<-tick.C
			atomic.StoreUint32(&handleThrottleCount, 0)
		}
	}()

	r := &registryProcessor{
		keys:   make(map[uint64]string),
		hsnap:  hsnap,
		values: make(map[uint32][]*event.Event),
		purger: time.NewTicker(valuePurgerInterval),
		quit:   make(chan struct{}, 1),
	}

	go r.housekeep()

	return r
}

func (r *registryProcessor) ProcessEvent(e *event.Event) (*event.Event, bool, error) {
	if e.Category == event.Registry {
		evt, err := r.processEvent(e)
		return evt, false, err
	}
	return e, true, nil
}

func (r *registryProcessor) processEvent(e *event.Event) (*event.Event, error) {
	switch e.Type {
	case event.RegKCBRundown, event.RegCreateKCB:
		khandle := e.Params.MustGetUint64(params.RegKeyHandle)
		r.keys[khandle] = e.Params.MustGetString(params.RegPath)
		kcbCount.Add(1)
	case event.RegDeleteKCB:
		khandle := e.Params.MustGetUint64(params.RegKeyHandle)
		delete(r.keys, khandle)
		kcbCount.Add(-1)
	default:
		if e.IsRegSetValueInternal() {
			// store the event in temporary queue
			r.pushSetValue(e)
			return e, nil
		}

		khandle := e.Params.MustGetUint64(params.RegKeyHandle)
		// we have to obey a straightforward algorithm to connect relative
		// key names to their root keys. If key handle is equal to zero we
		// have a full key name and don't have to go further resolving the
		// missing part. Otherwise, we have to lookup existing KCBs to try
		// finding the matching base key name and concatenate to its relative
		// path. If none of the aforementioned checks are successful, our
		// last resort is to scan process' handles and check if any of the
		// key handles contain the partial key name. In this case we assume
		// the correct key is encountered.
		keyName := e.Params.MustGetString(params.RegPath)
		if khandle != 0 {
			if baseKey, ok := r.keys[khandle]; ok {
				keyName = baseKey + "\\" + keyName
			} else {
				kcbMissCount.Add(1)
				keyName = r.findMatchingKey(e.PID, keyName)
			}
			if err := e.Params.SetValue(params.RegPath, keyName); err != nil {
				return e, err
			}
		}

		if e.IsRegSetValue() {
			// previously stored RegSetValueInternal event
			// is popped from the queue. RegSetValue can
			// be enriched with registry value type/data
			v := r.popSetValue(e)
			if v == nil {
				// try to read captured data from userspace
				goto readValue
			}

			capturedDataHits.Add(1)

			// enrich the event with value data/type parameters
			typ, err := v.Params.GetUint32(params.RegValueType)
			if err == nil {
				e.AppendEnum(params.RegValueType, typ, key.RegistryValueTypes)
			}
			data, err := v.Params.Get(params.RegData)
			if err == nil {
				e.AppendParam(params.RegData, data.Type, data.Value)
			}

			return e, nil
		}

	readValue:
		if !e.IsRegSetValue() || !e.IsSuccess() {
			return e, nil
		}

		// values within hidden keys cannot be read
		if strings.HasSuffix(keyName, "\\") {
			return e, nil
		}

		// get the type/value of the registry key and append to parameters
		rootkey, subkey := key.Format(keyName)
		if rootkey == key.Invalid {
			return e, nil
		}

		readValueOps.Add(1)
		typ, val, err := rootkey.ReadValue(subkey)
		if err != nil {
			errno, ok := err.(windows.Errno)
			if ok && (errno.Is(os.ErrNotExist) || err == windows.ERROR_ACCESS_DENIED) {
				return e, nil
			}
			return e, ErrReadValue(rootkey.String(), keyName, err)
		}
		e.AppendEnum(params.RegValueType, typ, key.RegistryValueTypes)

		switch typ {
		case registry.SZ, registry.EXPAND_SZ:
			e.AppendParam(params.RegData, params.UnicodeString, val)
		case registry.MULTI_SZ:
			e.AppendParam(params.RegData, params.Slice, val)
		case registry.BINARY:
			e.AppendParam(params.RegData, params.Binary, val)
		case registry.QWORD:
			e.AppendParam(params.RegData, params.Uint64, val)
		case registry.DWORD:
			e.AppendParam(params.RegData, params.Uint32, uint32(val.(uint64)))
		}
	}

	return e, nil
}

func (*registryProcessor) Name() ProcessorType { return Registry }
func (r *registryProcessor) Close()            { r.quit <- struct{}{} }

func (r *registryProcessor) findMatchingKey(pid uint32, relativeKeyName string) string {
	// we want to prevent too frequent queries on the process' handles
	// since that can cause significant performance overhead. When throttle
	// count is greater than the max permitted value we'll just return the
	// partial key and hold on querying the handles of target process
	atomic.AddUint32(&handleThrottleCount, 1)
	if atomic.LoadUint32(&handleThrottleCount) > maxHandleQueries {
		return relativeKeyName
	}

	handles, err := r.hsnap.FindHandles(pid)
	if err != nil {
		return relativeKeyName
	}

	for _, h := range handles {
		if h.Type != handle.Key {
			continue
		}
		if strings.HasSuffix(h.Name, relativeKeyName) {
			keyHandleHits.Add(1)
			return h.Name
		}
	}

	return relativeKeyName
}

// pushSetValue stores the internal RegSetValue event
// into per process identifier queue.
func (r *registryProcessor) pushSetValue(e *event.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	vals, ok := r.values[e.PID]
	if !ok {
		r.values[e.PID] = []*event.Event{e}
	} else {
		r.values[e.PID] = append(vals, e)
	}
}

// popSetValue traverses the internal RegSetValue queue
// and pops the event if the suffixes match.
func (r *registryProcessor) popSetValue(e *event.Event) *event.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	vals, ok := r.values[e.PID]
	if !ok {
		return nil
	}

	var v *event.Event
	for i := len(vals) - 1; i >= 0; i-- {
		val := vals[i]
		if strings.HasSuffix(e.GetParamAsString(params.RegPath), val.GetParamAsString(params.RegPath)) {
			v = val
			r.values[e.PID] = append(vals[:i], vals[i+1:]...)
			break
		}
	}

	return v
}

func (r *registryProcessor) valuesSize(pid uint32) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.values[pid])
}

func (r *registryProcessor) housekeep() {
	for {
		select {
		case <-r.purger.C:
			r.mu.Lock()
			for pid, vals := range r.values {
				for i, val := range vals {
					if time.Since(val.Timestamp) < valueTTL {
						continue
					}
					r.values[pid] = append(vals[:i], vals[i+1:]...)
				}
				if len(vals) == 0 {
					delete(r.values, pid)
				}
			}
			r.mu.Unlock()
		case <-r.quit:
			return
		}
	}
}

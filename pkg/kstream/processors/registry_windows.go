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
	"sync/atomic"
	"time"

	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
)

var (
	// ErrReadValue describes an error occurred while reading the registry value
	ErrReadValue = func(key, subkey string, err error) error {
		return fmt.Errorf("unable to read value %s : %v", filepath.Join(key, subkey), err)
	}

	// kcbCount counts the total KCBs found during the duration of the kernel session
	kcbCount      = expvar.NewInt("registry.kcb.count")
	kcbMissCount  = expvar.NewInt("registry.kcb.misses")
	keyHandleHits = expvar.NewInt("registry.key.handle.hits")

	handleThrottleCount uint32
)

const (
	maxHandleQueries = 200
)

type registryProcessor struct {
	// keys stores the mapping between the KCB (Key Control Block) and the key name.
	keys  map[uint64]string
	hsnap handle.Snapshotter
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
	return &registryProcessor{
		keys:  make(map[uint64]string),
		hsnap: hsnap,
	}
}

func (r *registryProcessor) ProcessEvent(e *kevent.Kevent) (*kevent.Kevent, bool, error) {
	if e.Category == ktypes.Registry {
		evt, err := r.processEvent(e)
		return evt, false, err
	}
	return e, true, nil
}

func (r *registryProcessor) processEvent(e *kevent.Kevent) (*kevent.Kevent, error) {
	switch e.Type {
	case ktypes.RegKCBRundown, ktypes.RegCreateKCB:
		khandle := e.Kparams.MustGetUint64(kparams.RegKeyHandle)
		if _, ok := r.keys[khandle]; !ok {
			r.keys[khandle], _ = e.Kparams.GetString(kparams.RegKeyName)
		}
		kcbCount.Add(1)
	case ktypes.RegDeleteKCB:
		khandle := e.Kparams.MustGetUint64(kparams.RegKeyHandle)
		delete(r.keys, khandle)
		kcbCount.Add(-1)
	default:
		khandle := e.Kparams.MustGetUint64(kparams.RegKeyHandle)
		// we have to obey a straightforward algorithm to connect relative
		// key names to their root keys. If key handle is equal to zero we
		// have a full key name and don't have to go further resolving the
		// missing part. Otherwise, we have to lookup existing KCBs to try
		// finding the matching base key name and concatenate to its relative
		// path. If none of the aforementioned checks are successful, our
		// last resort is to scan process' handles and check if any of the
		// key handles contain the partial key name. In this case we assume
		// the correct key is encountered.
		keyName := e.Kparams.MustGetString(kparams.RegKeyName)
		if khandle != 0 {
			if baseKey, ok := r.keys[khandle]; ok {
				keyName = baseKey + "\\" + keyName
			} else {
				kcbMissCount.Add(1)
				keyName = r.findMatchingKey(e.PID, keyName)
			}
			if err := e.Kparams.SetValue(kparams.RegKeyName, keyName); err != nil {
				return e, err
			}
		}

		// get the type/value of the registry key and append to parameters
		if !e.IsRegSetValue() || !e.IsSuccess() {
			return e, nil
		}

		rootkey, subkey := key.Format(keyName)
		if rootkey != key.Invalid {
			typ, val, err := rootkey.ReadValue(subkey)
			if err != nil {
				errno, ok := err.(windows.Errno)
				if ok && (errno.Is(os.ErrNotExist) || err == windows.ERROR_ACCESS_DENIED) {
					return e, nil
				}
				return e, ErrReadValue(rootkey.String(), keyName, err)
			}
			e.AppendEnum(kparams.RegValueType, typ, key.RegistryValueTypes)
			switch typ {
			case registry.SZ, registry.EXPAND_SZ:
				e.AppendParam(kparams.RegValue, kparams.UnicodeString, val)
			case registry.MULTI_SZ:
				e.AppendParam(kparams.RegValue, kparams.Slice, val)
			case registry.BINARY:
				e.AppendParam(kparams.RegValue, kparams.Binary, val)
			case registry.QWORD:
				e.AppendParam(kparams.RegValue, kparams.Uint64, val)
			case registry.DWORD:
				e.AppendParam(kparams.RegValue, kparams.Uint32, uint32(val.(uint64)))
			}
		}
	}
	return e, nil
}

func (registryProcessor) Name() ProcessorType { return Registry }
func (registryProcessor) Close()              {}

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

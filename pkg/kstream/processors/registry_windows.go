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
	"github.com/rabbitstack/fibratus/pkg/util/key"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	reg "golang.org/x/sys/windows/registry"
)

var (
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

func (r *registryProcessor) ProcessEvent(kevt *kevent.Kevent) (*kevent.Kevent, bool, error) {
	if kevt.Category == ktypes.Registry {
		err := r.processEvent(kevt)
		return kevt, false, err
	}
	return kevt, true, nil
}

func (registryProcessor) Name() ProcessorType { return Registry }
func (registryProcessor) Close()              {}

func (r *registryProcessor) processEvent(kevt *kevent.Kevent) error {
	switch kevt.Type {
	case ktypes.RegKCBRundown, ktypes.RegCreateKCB:
		khandle := kevt.Kparams.MustGetUint64(kparams.RegKeyHandle)
		if _, ok := r.keys[khandle]; !ok {
			r.keys[khandle], _ = kevt.Kparams.GetString(kparams.RegKeyName)
		}
		kcbCount.Add(1)
	case ktypes.RegDeleteKCB:
		khandle := kevt.Kparams.MustGetUint64(kparams.RegKeyHandle)
		delete(r.keys, khandle)
		kcbCount.Add(-1)
	default:
		khandle := kevt.Kparams.MustGetUint64(kparams.RegKeyHandle)
		// we have to obey a straightforward algorithm to connect relative
		// key names to their root keys. If key handle is equal to zero we
		// have a full key name and don't have to go further resolving the
		// missing part. Otherwise, we have to lookup existing KCBs to try
		// find the matching base key name and concatenate to its relative
		// path. If none of the aforementioned checks are successful, our
		// last resort is to scan process' handles and check if any of the
		// key handles contain the partial key name. In this case we assume
		// the correct key is encountered.
		keyName, _ := kevt.Kparams.GetString(kparams.RegKeyName)
		if khandle != 0 {
			if baseKey, ok := r.keys[khandle]; ok {
				keyName = baseKey + "\\" + keyName
			} else {
				kcbMissCount.Add(1)
				keyName = r.findMatchingKey(kevt.PID, keyName)
			}
			if err := kevt.Kparams.SetValue(kparams.RegKeyName, keyName); err != nil {
				return err
			}
		}

		// get the type/value of the registry key and append to parameters
		if kevt.IsRegSetValue() {
			rootKey, keyName := key.Format(keyName)
			if rootKey != key.Invalid {
				subkey, value := filepath.Split(keyName)
				regKey, err := reg.OpenKey(rootKey, subkey, reg.QUERY_VALUE)
				if err != nil {
					return err
				}
				defer regKey.Close()
				b := make([]byte, 0)
				_, typ, err := regKey.GetValue(value, b)
				if err != nil {
					return err
				}
				// append value type parameter
				kevt.AppendParam(kparams.RegValueType, kparams.Enum, typ, kevent.WithEnum(key.RegistryValueTypes))
				switch typ {
				case reg.SZ, reg.EXPAND_SZ:
					v, _, err := regKey.GetStringValue(value)
					if err != nil {
						return err
					}
					kevt.Kparams.Append(kparams.RegValue, kparams.UnicodeString, v)
				case reg.DWORD, reg.QWORD:
					v, _, err := regKey.GetIntegerValue(value)
					if err != nil {
						return err
					}
					kevt.Kparams.Append(kparams.RegValue, kparams.Uint64, v)
				case reg.MULTI_SZ:
					v, _, err := regKey.GetStringsValue(value)
					if err != nil {
						return err
					}
					kevt.Kparams.Append(kparams.RegValue, kparams.UnicodeString, strings.Join(v, "\n\r"))
				case reg.BINARY:
					v, _, err := regKey.GetBinaryValue(value)
					if err != nil {
						return err
					}
					kevt.Kparams.Append(kparams.RegValue, kparams.UnicodeString, string(v))
				}
			}
		}
	}
	return nil
}

func (r *registryProcessor) findMatchingKey(pid uint32, relativeKeyName string) string {
	// we want to prevent too frequent queries on the process' handles
	// since that can cause significant performance overhead. When throttle
	// count is greater than the max permitted value we'll just return the partial key
	// and hold on querying the handles of target process
	atomic.AddUint32(&handleThrottleCount, 1)
	if handleThrottleCount > maxHandleQueries {
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

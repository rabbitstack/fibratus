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
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/syscall/registry"
	reg "golang.org/x/sys/windows/registry"
)

var (
	// kcbCount counts the total KCBs found during the duration of the kernel session
	kcbCount         = expvar.NewInt("registry.kcb.count")
	kcbMissCount     = expvar.NewInt("registry.kcb.misses")
	unknownKeysCount = expvar.NewInt("registry.unknown.keys.count")
	keyHandleHits    = expvar.NewInt("registry.key.handle.hits")

	handleThrottleCount uint32
)

const (
	notFoundNTStatus = 3221225524
	maxHandleQueries = 200
)

type registryInterceptor struct {
	// keys stores the mapping between the KCB (Key Control Block) and the key name.
	keys  map[uint64]string
	hsnap handle.Snapshotter
}

func newRegistryInterceptor(hsnap handle.Snapshotter) KstreamInterceptor {
	// schedule a ticker that resets the throttle count every minute
	tick := time.NewTicker(time.Minute)
	go func() {
		for {
			<-tick.C
			atomic.StoreUint32(&handleThrottleCount, 0)
		}
	}()
	return &registryInterceptor{keys: make(map[uint64]string), hsnap: hsnap}
}

func (r *registryInterceptor) Intercept(kevt *kevent.Kevent) (*kevent.Kevent, bool, error) {
	typ := kevt.Type
	switch typ {
	case ktypes.RegKCBRundown, ktypes.RegCreateKCB:
		khandle, err := kevt.Kparams.GetHexAsUint64(kparams.RegKeyHandle)
		if err != nil {
			return kevt, true, err
		}
		if _, ok := r.keys[khandle]; !ok {
			r.keys[khandle], _ = kevt.Kparams.GetString(kparams.RegKeyName)
		}
		kcbCount.Add(1)
		return kevt, false, nil

	case ktypes.RegDeleteKCB:
		khandle, err := kevt.Kparams.GetHexAsUint64(kparams.RegKeyHandle)
		if err != nil {
			return kevt, true, err
		}
		delete(r.keys, khandle)
		kcbCount.Add(-1)
		return kevt, false, nil

	case ktypes.RegCreateKey,
		ktypes.RegDeleteKey,
		ktypes.RegOpenKey, ktypes.RegOpenKeyV1,
		ktypes.RegQueryKey,
		ktypes.RegQueryValue,
		ktypes.RegSetValue,
		ktypes.RegDeleteValue:
		khandle, err := kevt.Kparams.GetHexAsUint64(kparams.RegKeyHandle)
		if err != nil {
			return kevt, true, err
		}
		// we have to obey a straightforward algorithm to connect relative
		// key names to their root keys. If key handle is equal to zero we
		// have a full key name and don't have to go further resolving the
		// missing part. Otherwise, we have to lookup existing KCBs to try
		// find the matching base key name and concatenate to its relative
		// path. If none of the aforementioned checks are successful, our
		// last resort is to scan process' handles and check if any of the
		// key handles contain the partial key name. In this case we assume
		// the correct key is encountered.
		var rootKey registry.Key
		keyName, err := kevt.Kparams.GetString(kparams.RegKeyName)
		if err != nil {
			return kevt, true, err
		}
		if khandle != 0 {
			if baseKey, ok := r.keys[khandle]; ok {
				keyName = baseKey + "\\" + keyName
			} else {
				kcbMissCount.Add(1)
				keyName = r.findMatchingKey(kevt.PID, keyName)
			}
		}

		if keyName != "" {
			rootKey, keyName = handle.FormatKey(keyName)
			k := rootKey.String()
			if keyName != "" && rootKey != registry.InvalidKey {
				k += "\\" + keyName
			}
			if rootKey == registry.InvalidKey {
				unknownKeysCount.Add(1)
				k = keyName
			}
			if err := kevt.Kparams.Set(kparams.RegKeyName, k, kparams.UnicodeString); err != nil {
				return kevt, true, err
			}
		}

		// format registry operation status code
		status, err := kevt.Kparams.GetUint32(kparams.NTStatus)
		if err == nil {
			_ = kevt.Kparams.Set(kparams.NTStatus, formatStatus(status), kparams.UnicodeString)
		}

		// get the type/value of the registry key and append to parameters
		if typ == ktypes.RegSetValue {
			if rootKey != registry.InvalidKey {
				subkey, value := filepath.Split(keyName)
				key, err := reg.OpenKey(reg.Key(rootKey), subkey, reg.QUERY_VALUE)
				if err != nil {
					return kevt, true, nil
				}
				defer key.Close()
				b := make([]byte, 0)
				_, typ, err := key.GetValue(value, b)
				if err != nil {
					return kevt, true, nil
				}
				kevt.Kparams.Append(kparams.RegValueType, kparams.AnsiString, typToString(typ))
				switch typ {
				case reg.SZ, reg.EXPAND_SZ:
					v, _, err := key.GetStringValue(value)
					if err != nil {
						return kevt, true, nil
					}
					kevt.Kparams.Append(kparams.RegValue, kparams.UnicodeString, v)

				case reg.DWORD, reg.QWORD:
					v, _, err := key.GetIntegerValue(value)
					if err != nil {
						return kevt, true, nil
					}
					kevt.Kparams.Append(kparams.RegValue, kparams.Uint64, v)

				case reg.MULTI_SZ:
					v, _, err := key.GetStringsValue(value)
					if err != nil {
						return kevt, true, nil
					}
					kevt.Kparams.Append(kparams.RegValue, kparams.UnicodeString, strings.Join(v, "\n\r"))

				case reg.BINARY:
					v, _, err := key.GetBinaryValue(value)
					if err != nil {
						return kevt, true, nil
					}
					kevt.Kparams.Append(kparams.RegValue, kparams.UnicodeString, string(v))
				}
				return kevt, false, nil
			}
		}
	}

	return kevt, true, nil
}

func (registryInterceptor) Name() InterceptorType { return Registry }
func (registryInterceptor) Close()                {}

func typToString(typ uint32) string {
	switch typ {
	case reg.DWORD:
		return "REG_DWORD"
	case reg.QWORD:
		return "REG_QWORD"
	case reg.SZ:
		return "REG_SZ"
	case reg.EXPAND_SZ:
		return "REG_EXPAND_SZ"
	case reg.MULTI_SZ:
		return "REG_MULTI_SZ"
	case reg.BINARY:
		return "REG_BINARY"
	default:
		return "UNKNOWN"
	}
}

func (r *registryInterceptor) findMatchingKey(pid uint32, relativeKeyName string) string {
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

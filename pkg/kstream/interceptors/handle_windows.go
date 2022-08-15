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
	"time"

	kerrors "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	syshandle "github.com/rabbitstack/fibratus/pkg/syscall/handle"
	"github.com/rabbitstack/fibratus/pkg/syscall/registry"
)

var (
	handleDeferEvictions = expvar.NewInt("handle.deferred.evictions")
	handleDeferMatches   = expvar.NewInt("handle.deferred.matches")
)

// waitPeriod specifies the interval for which the accumulated
// CreateHandle events are drained from the map
var waitPeriod = time.Second * 5

type handleInterceptor struct {
	hsnap         handle.Snapshotter
	typeStore     handle.ObjectTypeStore
	devMapper     fs.DevMapper
	defers        map[uint64]*kevent.Kevent
	deferredKevts chan *kevent.Kevent
}

func newHandleInterceptor(hsnap handle.Snapshotter, typeStore handle.ObjectTypeStore, devMapper fs.DevMapper, defferedKevts chan *kevent.Kevent) KstreamInterceptor {
	return &handleInterceptor{
		hsnap:         hsnap,
		typeStore:     typeStore,
		devMapper:     devMapper,
		defers:        make(map[uint64]*kevent.Kevent),
		deferredKevts: defferedKevts,
	}
}

func (h *handleInterceptor) Intercept(kevt *kevent.Kevent) (*kevent.Kevent, bool, error) {
	if kevt.Type == ktypes.CreateHandle || kevt.Type == ktypes.CloseHandle {
		handleID, err := kevt.Kparams.TryGetHexAsUint32(kparams.HandleID)
		if err == nil {
			// if the param was in hex representation, convert to uint32
			_ = kevt.Kparams.Set(kparams.HandleID, handleID, kparams.Uint32)
		}
		typeID, err := kevt.Kparams.GetUint16(kparams.HandleObjectTypeID)
		if err != nil {
			return kevt, true, err
		}
		object, err := kevt.Kparams.TryGetHexAsUint64(kparams.HandleObject)
		if err != nil {
			return kevt, true, err
		}
		// map object type identifier to its name. Query for object type if
		// we didn't find in the object store
		typeName := h.typeStore.FindByID(uint8(typeID))
		if typeName == "" {
			dup, err := handle.Duplicate(syshandle.Handle(handleID), kevt.PID, syshandle.AllAccess)
			if err != nil {
				return kevt, true, err
			}
			defer dup.Close()
			typeName, err = handle.QueryType(dup)
			if err != nil {
				return kevt, true, err
			}
			h.typeStore.RegisterType(uint8(typeID), typeName)
		}

		kevt.Kparams.Append(kparams.HandleObjectTypeName, kparams.AnsiString, typeName)
		kevt.Kparams.Remove(kparams.HandleObjectTypeID)

		// get the best possible object name according to its type
		name, err := kevt.Kparams.GetString(kparams.HandleObjectName)
		if err != nil {
			return kevt, true, err
		}

		switch typeName {
		case handle.Key:
			rootKey, keyName := handle.FormatKey(name)
			if rootKey == registry.InvalidKey {
				break
			}
			name = rootKey.String()
			if keyName != "" {
				name += "\\" + keyName
			}
		case handle.File:
			name = h.devMapper.Convert(name)
		}
		// assign the formatted handle name
		if err := kevt.Kparams.Set(kparams.HandleObjectName, name, kparams.AnsiString); err != nil {
			return kevt, true, err
		}

		if kevt.Type == ktypes.CreateHandle {
			// for some handle objects, the CreateHandle usually lacks the handle name
			// but its counterpart CloseHandle kevent ships with the handle name. We'll
			// defer emitting the CreateHandle kevent until we receive a CloseHandle targeting
			// the same object
			if name == "" && (typeName == handle.Key || typeName == handle.File ||
				typeName == handle.Desktop || typeName == handle.SymbolicLink) {
				h.defers[object] = kevt
				return kevt, false, kerrors.ErrCancelUpstreamKevent
			}
			return kevt, false, h.hsnap.Write(kevt)
		}

		// at this point we hit CloseHandle kernel event and have the awaiting CreateHandle
		// event reference. So we set handle object name to the name of its CloseHandle counterpart
		if hkevt, ok := h.defers[object]; ok {
			delete(h.defers, object)

			if err := hkevt.Kparams.Set(kparams.HandleObjectName, name, kparams.AnsiString); err != nil {
				return kevt, true, err
			}
			handleDeferMatches.Add(1)

			// send the deferred event
			select {
			case h.deferredKevts <- hkevt:
			default:
			}

			err := h.hsnap.Write(hkevt)
			if err != nil {
				err = h.hsnap.Remove(kevt)
				if err != nil {
					return kevt, false, err
				}
			}

			// return the CloseHandle event
			return kevt, false, h.hsnap.Remove(kevt)
		}
		// drain pending CreateHandle kevents if they remained longer then expected. Possible
		// cause could be that we lost the corresponding CloseHandle kernel event or the
		// CreateHandle event was produced but the corresponding CloseHandle event will happen
		// during the longer time frame
		for kobj, kvt := range h.defers {
			evict := kvt.Timestamp.Before(time.Now().Add(waitPeriod))
			if evict {
				handleDeferEvictions.Add(1)
				delete(h.defers, kobj)
				// push the CreateHandle event
				select {
				case h.deferredKevts <- kvt:
				default:
				}
			}
		}
		return kevt, false, h.hsnap.Remove(kevt)
	}

	return kevt, true, nil
}

func (handleInterceptor) Name() InterceptorType { return Handle }
func (handleInterceptor) Close()                {}

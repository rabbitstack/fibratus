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
	"github.com/rabbitstack/fibratus/pkg/syscall/driver"
	"github.com/rabbitstack/fibratus/pkg/util/key"
	"path/filepath"
	"strings"
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
	handleDeferMatches = expvar.NewInt("handle.deferred.matches")
)

// waitPeriod specifies the interval for which the accumulated
// CreateHandle events are drained from the map
var waitPeriod = time.Second * 5

type handleProcessor struct {
	hsnap     handle.Snapshotter
	typeStore handle.ObjectTypeStore
	devMapper fs.DevMapper
	objects   map[uint64]*kevent.Kevent
}

func newHandleProcessor(
	hsnap handle.Snapshotter,
	typeStore handle.ObjectTypeStore,
	devMapper fs.DevMapper,
) Processor {
	return &handleProcessor{
		hsnap:     hsnap,
		typeStore: typeStore,
		devMapper: devMapper,
		objects:   make(map[uint64]*kevent.Kevent, 1000),
	}
}

func (h *handleProcessor) ProcessEvent(kevt *kevent.Kevent) (*kevent.Kevent, bool, error) {
	if kevt.Category == ktypes.Handle {
		output, err := h.processEvent(kevt)
		return output, false, err
	}
	return kevt, true, nil
}

func (h *handleProcessor) processEvent(kevt *kevent.Kevent) (*kevent.Kevent, error) {
	handleID, err := kevt.Kparams.GetUint32(kparams.HandleID)
	if err != nil {
		return kevt, err
	}
	typeID, err := kevt.Kparams.GetUint16(kparams.HandleObjectTypeID)
	if err != nil {
		return kevt, err
	}
	object, err := kevt.Kparams.GetUint64(kparams.HandleObject)
	if err != nil {
		return kevt, err
	}
	// map object type identifier to its name. Query for object type if
	// we didn't find in the object store
	typeName := h.typeStore.FindByID(uint8(typeID))
	if typeName == "" {
		dup, err := handle.Duplicate(syshandle.Handle(handleID), kevt.PID, syshandle.AllAccess)
		if err != nil {
			return kevt, err
		}
		defer dup.Close()
		typeName, err = handle.QueryType(dup)
		if err != nil {
			return kevt, err
		}
		h.typeStore.RegisterType(uint8(typeID), typeName)
	}

	kevt.Kparams.Append(kparams.HandleObjectTypeName, kparams.AnsiString, typeName)
	kevt.Kparams.Remove(kparams.HandleObjectTypeID)

	// get the best possible object name according to its type
	name, err := kevt.Kparams.GetString(kparams.HandleObjectName)
	if err != nil {
		return kevt, err
	}

	switch typeName {
	case handle.Key:
		rootKey, keyName := key.Format(name)
		if rootKey == registry.InvalidKey {
			break
		}
		name = rootKey.String()
		if keyName != "" {
			name += "\\" + keyName
		}
	case handle.File:
		name = h.devMapper.Convert(name)
	case handle.Driver:
		driverName := strings.TrimPrefix(name, "\\Driver\\") + ".sys"
		drivers := driver.EnumDevices()
		for _, drv := range drivers {
			if strings.EqualFold(filepath.Base(drv.Filename), driverName) {
				kevt.Kparams.Append(kparams.ImageFilename, kparams.FilePath, drv.Filename)
			}
		}
	}
	// assign the formatted handle name
	if err := kevt.Kparams.SetValue(kparams.HandleObjectName, name); err != nil {
		return kevt, err
	}

	if kevt.Type == ktypes.CreateHandle {
		// for some handle objects, the CreateHandle usually lacks the handle name
		// but its counterpart CloseHandle kevent ships with the handle name. We'll
		// defer emitting the CreateHandle kevent until we receive a CloseHandle targeting
		// the same object
		if name == "" {
			h.objects[object] = kevt
			return kevt, kerrors.ErrCancelUpstreamKevent
		}
		return kevt, h.hsnap.Write(kevt)
	}

	// at this point we hit CloseHandle kernel event and have the awaiting CreateHandle
	// event reference. So we set handle object name to the name of its CloseHandle counterpart
	if hkevt, ok := h.objects[object]; ok {
		delete(h.objects, object)
		if err := hkevt.Kparams.SetValue(kparams.HandleObjectName, name); err != nil {
			return kevt, err
		}
		handleDeferMatches.Add(1)

		if typeName == handle.Driver {
			driverFilename := kevt.GetParamAsString(kparams.ImageFilename)
			hkevt.Kparams.Append(kparams.ImageFilename, kparams.FilePath, driverFilename)
		}

		err := h.hsnap.Write(hkevt)
		if err != nil {
			err = h.hsnap.Remove(kevt)
			if err != nil {
				return kevt, err
			}
		}

		// return the CreateHandle event
		return hkevt, h.hsnap.Remove(kevt)
	}
	return kevt, h.hsnap.Remove(kevt)
}

func (handleProcessor) Name() ProcessorType { return Handle }
func (h *handleProcessor) Close()           {}

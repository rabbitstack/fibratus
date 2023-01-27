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
	"github.com/golang/groupcache/lru"
	kerrors "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/syscall/driver"
	syshandle "github.com/rabbitstack/fibratus/pkg/syscall/handle"
	"github.com/rabbitstack/fibratus/pkg/util/key"
	"path/filepath"
	"strings"
)

// maxLRUCacheSize specified the maximum number of objects waiting for the CreateHandle event
const maxLRUCacheSize = 1000

var (
	handleDeferMatches = expvar.NewInt("handle.deferred.matches")
)

type handleProcessor struct {
	hsnap     handle.Snapshotter
	typeStore handle.ObjectTypeStore
	devMapper fs.DevMapper
	objects   *lru.Cache
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
		objects:   lru.New(maxLRUCacheSize),
	}
}

func (h *handleProcessor) ProcessEvent(e *kevent.Kevent) (*kevent.Batch, bool, error) {
	if e.Category == ktypes.Handle {
		evts, err := h.processEvent(e)
		return evts, false, err
	}
	return nil, true, nil
}

func (h *handleProcessor) processEvent(e *kevent.Kevent) (*kevent.Batch, error) {
	handleID := e.Kparams.MustGetUint32(kparams.HandleID)
	typeID := e.Kparams.MustGetUint16(kparams.HandleObjectTypeID)
	object := e.Kparams.MustGetUint64(kparams.HandleObject)
	// map object type identifier to its name. Query the object type if
	// it wasn't find in the object store and register the missing type
	typeName := h.typeStore.FindByID(uint8(typeID))
	if typeName == "" {
		dup, err := handle.Duplicate(syshandle.Handle(handleID), e.PID, syshandle.AllAccess)
		if err != nil {
			return kevent.NewBatch(e), err
		}
		defer dup.Close()
		typeName, err = handle.QueryType(dup)
		if err != nil {
			return kevent.NewBatch(e), err
		}
		h.typeStore.RegisterType(uint8(typeID), typeName)
	}
	e.Kparams.Append(kparams.HandleObjectTypeName, kparams.AnsiString, typeName)

	// get the best possible object name according to its type
	name := e.GetParamAsString(kparams.HandleObjectName)
	if name != "" {
		switch typeName {
		case handle.Key:
			rootKey, keyName := key.Format(name)
			if rootKey == key.Invalid {
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
					e.Kparams.Append(kparams.ImageFilename, kparams.FilePath, drv.Filename)
				}
			}
		}
	}

	// assign the formatted handle name
	if err := e.Kparams.SetValue(kparams.HandleObjectName, name); err != nil {
		return kevent.NewBatch(e), err
	}

	if e.Type == ktypes.CreateHandle {
		// CreateHandle events lack the handle name
		// but its counterpart CloseHandle event has
		// the handle name. We'll defer emitting the
		// CreateHandle event until we receive a CloseHandle
		// targeting the same object. If the cache capacity is
		// over the specified threshold, remove the oldest entry
		if h.objects.Len() > maxLRUCacheSize {
			h.objects.RemoveOldest()
		}
		h.objects.Add(object, e)
		return nil, kerrors.ErrCancelUpstreamKevent
	}

	// at this point we hit CloseHandle kernel event and have the awaiting CreateHandle
	// event reference. So we set handle object name to the name of its CloseHandle counterpart
	if o, ok := h.objects.Get(object); ok {
		evt := o.(*kevent.Kevent)
		h.objects.Remove(object)
		if err := evt.Kparams.SetValue(kparams.HandleObjectName, name); err != nil {
			return kevent.NewBatch(e), err
		}
		handleDeferMatches.Add(1)

		if typeName == handle.Driver {
			driverFilename := e.GetParamAsString(kparams.ImageFilename)
			evt.Kparams.Append(kparams.ImageFilename, kparams.FilePath, driverFilename)
		}
		err := h.hsnap.Write(evt)
		if err != nil {
			err = h.hsnap.Remove(e)
			if err != nil {
				return kevent.NewBatch(e), err
			}
		}
		// return the CreateHandle+CloseHandle batch
		return kevent.NewBatch(evt, e), h.hsnap.Remove(e)
	}
	return kevent.NewBatch(e), h.hsnap.Remove(e)
}

func (handleProcessor) Name() ProcessorType { return Handle }
func (h *handleProcessor) Close()           {}

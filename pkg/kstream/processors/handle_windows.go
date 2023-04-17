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
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/key"
	"path/filepath"
	"strings"
)

type handleProcessor struct {
	hsnap     handle.Snapshotter
	devMapper fs.DevMapper
}

func newHandleProcessor(
	hsnap handle.Snapshotter,
	devMapper fs.DevMapper,
) Processor {
	return &handleProcessor{
		hsnap:     hsnap,
		devMapper: devMapper,
	}
}

func (h *handleProcessor) ProcessEvent(e *kevent.Kevent) (*kevent.Kevent, bool, error) {
	if e.Category == ktypes.Handle {
		evt, err := h.processEvent(e)
		return evt, false, err
	}
	return e, true, nil
}

func (h *handleProcessor) processEvent(e *kevent.Kevent) (*kevent.Kevent, error) {
	name := e.GetParamAsString(kparams.HandleObjectName)
	typ := e.GetParamAsString(kparams.HandleObjectTypeName)

	if name != "" {
		switch typ {
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
			drivers := sys.EnumDevices()
			for _, drv := range drivers {
				if strings.EqualFold(filepath.Base(drv.Filename), driverName) {
					e.Kparams.Append(kparams.ImageFilename, kparams.FilePath, drv.Filename)
				}
			}
		}
	}

	// assign the formatted handle name
	if err := e.Kparams.SetValue(kparams.HandleObjectName, name); err != nil {
		return e, err
	}

	object := e.Kparams.MustGetUint64(kparams.HandleObject)
	e.AddMeta(kevent.DelayComparatorKey, object)

	if e.Type == ktypes.CreateHandle {
		e.Delayed = true
		return e, h.hsnap.Write(e)
	}

	return e, h.hsnap.Remove(e)
}

func (handleProcessor) Name() ProcessorType { return Handle }
func (h *handleProcessor) Close()           {}

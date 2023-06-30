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
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/util/key"
	"strings"
)

type handleProcessor struct {
	hsnap           handle.Snapshotter
	psnap           ps.Snapshotter
	devMapper       fs.DevMapper
	devPathResolver fs.DevPathResolver
}

func newHandleProcessor(
	hsnap handle.Snapshotter,
	psnap ps.Snapshotter,
	devMapper fs.DevMapper,
	devPathResolver fs.DevPathResolver,
) Processor {
	return &handleProcessor{
		hsnap:           hsnap,
		psnap:           psnap,
		devMapper:       devMapper,
		devPathResolver: devPathResolver,
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
	if e.Type == ktypes.DuplicateHandle {
		// enrich event with process parameters
		pid := e.Kparams.MustGetPid()
		proc := h.psnap.FindAndPut(pid)
		if proc != nil {
			e.AppendParam(kparams.Exe, kparams.FilePath, proc.Exe)
			e.AppendParam(kparams.ProcessName, kparams.AnsiString, proc.Name)
		}
		return e, nil
	}

	name := e.GetParamAsString(kparams.HandleObjectName)
	typ := e.GetParamAsString(kparams.HandleObjectTypeID)

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
			driverPath := h.devPathResolver.GetPath(driverName)
			if driverPath == "" {
				driverPath = driverName
			}
			h.devPathResolver.RemovePath(driverName)
			e.Kparams.Append(kparams.ImageFilename, kparams.FilePath, driverPath)
		}
		// assign the formatted handle name
		if err := e.Kparams.SetValue(kparams.HandleObjectName, name); err != nil {
			return e, err
		}
	}

	if e.Type == ktypes.CreateHandle {
		return e, h.hsnap.Write(e)
	}

	return e, h.hsnap.Remove(e)
}

func (*handleProcessor) Name() ProcessorType { return Handle }
func (h *handleProcessor) Close()            {}

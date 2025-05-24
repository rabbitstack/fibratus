/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	psnap "github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/util/va"
)

// MemPageTypes represents the type of the pages in the allocated region.
var MemPageTypes = event.ParamEnum{
	va.MemImage:   "IMAGE",
	va.MemMapped:  "MAPPED",
	va.MemPrivate: "PRIVATE",
}

type memProcessor struct {
	psnap        psnap.Snapshotter
	regionProber *va.RegionProber
}

func newMemProcessor(psnap psnap.Snapshotter, regionProber *va.RegionProber) Processor {
	return &memProcessor{psnap: psnap, regionProber: regionProber}
}

func (memProcessor) Name() ProcessorType { return Mem }

func (m memProcessor) Close() {
	m.regionProber.Close()
}

func (m memProcessor) ProcessEvent(e *event.Event) (*event.Event, bool, error) {
	if e.Category == event.Mem {
		pid := e.Params.MustGetPid()
		if e.IsVirtualAlloc() {
			// retrieve info about the range of pages and enrich the event
			// with allocation protection options and the type of pages in
			// the allocated region. If the region is mapped, we try to find
			// the backing file name
			addr := e.Params.MustGetUint64(params.MemBaseAddress)
			region := m.regionProber.Query(pid, addr)
			if region != nil {
				if region.IsMapped() {
					e.AppendParam(params.FilePath, params.DOSPath, region.GetMappedFile())
				}
				e.AppendEnum(params.MemPageType, region.Type, MemPageTypes)
				e.AppendFlags(params.MemProtect, region.Protect, event.MemProtectionFlags)
				e.AppendParam(params.MemProtectMask, params.AnsiString, region.ProtectMask())
			}
		}
		proc := m.psnap.FindAndPut(pid)
		if proc != nil {
			e.AppendParam(params.Exe, params.Path, proc.Exe)
			e.AppendParam(params.ProcessName, params.AnsiString, proc.Name)
		}
		return e, false, nil
	}
	return e, true, nil
}

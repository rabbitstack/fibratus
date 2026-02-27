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
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/ps"
)

type moduleProcessor struct {
	psnap ps.Snapshotter
}

func newModuleProcessor(psnap ps.Snapshotter) Processor {
	m := &moduleProcessor{psnap: psnap}

	return m
}

func (*moduleProcessor) Name() ProcessorType { return Image }

func (m *moduleProcessor) ProcessEvent(e *event.Event) (*event.Event, bool, error) {
	if e.IsLoadImageInternal() {
		// state management
		return e, false, m.psnap.AddModule(e)
	}

	if e.IsUnloadImage() {
		pid := e.Params.MustGetPid()
		addr := e.Params.TryGetAddress(params.ImageBase)
		if pid == 0 {
			pid = e.PID
		}
		return e, false, m.psnap.RemoveModule(pid, addr)
	}

	if e.IsLoadImage() || e.IsImageRundown() {
		return e, false, m.psnap.AddModule(e)
	}

	return e, true, nil
}

func (m *moduleProcessor) Close() {}

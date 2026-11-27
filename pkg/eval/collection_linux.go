/*
 * Copyright 2026 by Nedim Sabic Sabic
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

package eval

import (
	"fmt"
	"maps"
	"slices"

	"github.com/rabbitstack/fibratus/pkg/callstack"
	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
)

// eachPlatform iterates over the collections that exist on Linux only.
func (e *ForeachEvaluator) eachPlatform(ctx *EvalCtx, collection any) any {
	switch items := collection.(type) {
	case map[uint32]pstypes.Thread:
		return loop(e, ctx, maps.Values(items), bindThread)
	case callstack.Callstack:
		return loop(e, ctx, slices.Values(items), bindFrame)
	}
	return false
}

func bindPlatformProcess(*binding, *pstypes.PS) {}

// bindThread exposes the thread information.
func bindThread(b *binding, thread pstypes.Thread) {
	for _, seg := range b.segments {
		switch seg.Segment {
		case fields.TidSegment:
			b.values[seg.Value] = thread.Tid
		case fields.PIDSegment:
			b.values[seg.Value] = thread.Pid
		}
	}
}

// bindFrame exposes the attributes of the stack frame.
func bindFrame(b *binding, frame callstack.Frame) {
	for _, seg := range b.segments {
		key := seg.Value
		switch seg.Segment {
		case fields.AddressSegment:
			b.values[key] = fmt.Sprintf("0x%x", frame.Addr)
		case fields.ModuleSegment:
			b.values[key] = frame.Module
		case fields.SymbolSegment:
			b.values[key] = frame.Module + "!" + frame.Symbol
		}
	}
}

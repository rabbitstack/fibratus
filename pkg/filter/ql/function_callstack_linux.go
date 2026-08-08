//go:build linux

/*
 * Copyright 2026 by Mostafa Moradian
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

package ql

import (
	"fmt"

	"github.com/rabbitstack/fibratus/pkg/callstack"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
)

func (f *Foreach) foreachCallstack(elems callstack.Callstack, segments []*BoundSegmentLiteral, e interface{}, useCallValuer bool, valuer MapValuer) (bool, bool) {
	for _, frame := range elems {
		if f.evalExpr(e, useCallValuer, f.callstackMapValuer(segments, frame), valuer) {
			return true, true
		}
	}
	return true, false
}

func (f *Foreach) callstackMapValuer(segments []*BoundSegmentLiteral, frame callstack.Frame) MapValuer {
	var valuer = MapValuer{}
	for _, seg := range segments {
		key := seg.Value
		switch seg.Segment {
		case fields.AddressSegment:
			valuer[key] = fmt.Sprintf("0x%x", frame.Addr)
		case fields.ModuleSegment:
			valuer[key] = frame.Module
		case fields.SymbolSegment:
			valuer[key] = frame.Module + "!" + frame.Symbol
		}
	}
	return valuer
}

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

package event

import (
	"fmt"
	"strconv"

	"github.com/rabbitstack/fibratus/pkg/util/colorizer"
)

// Format applies the template on the provided event.
func (f *Formatter) Format(evt *Event) []byte {
	if evt == nil {
		return []byte{}
	}

	values := f.eventMap(evt)

	ps := evt.PS
	if ps != nil {
		values[proc] = ps.Name
		values[ppid] = strconv.FormatUint(uint64(ps.Ppid), 10)
		values[cwd] = ps.Cwd
		values[exe] = ps.Exe
		values[cmd] = ps.Cmdline
		parent := ps.Parent

		if parent != nil {
			values[pproc] = parent.Name
			values[pexe] = parent.Exe
			values[pcmd] = parent.Cmdline
		}
	}

	if f.expandParamsDot {
		for _, par := range evt.Params {
			values[".Params."+caser.String(par.Name)] = par.String()
		}
	}

	return f.t.ExecuteString(values)
}

// colourTag maps a bare tag name to its coloured string representation.
func (f *ColorFormatter) colourTag(tag string, e *Event) string {
	switch tag {
	case seq:
		// sequence number is ok to render as dim gray
		return colorizer.SpanDim(colorizer.Span(colorizer.Gray, strconv.FormatUint(e.Seq, 10)))
	case ts:
		return f.colourTimestamp(e)
	case cpu:
		return colorizer.Span(colorizer.Yellow, strconv.FormatUint(uint64(e.CPU), 10))
	case proc:
		// render process name with bold green as it is the most important
		// identity anchor on the line. Analysts scan for it first.
		ps := e.PS
		if ps == nil {
			return colorizer.Span(colorizer.Gray, "N/A")
		}
		return colorizer.SpanBold(colorizer.Green, ps.Name)
	case pid:
		return colorizer.Span(colorizer.Green, strconv.FormatUint(uint64(e.PID), 10))
	case ppid:
		ps := e.PS
		if ps == nil {
			return colorizer.Span(colorizer.Gray, "N/A")
		}
		return colorizer.Span(colorizer.Green, strconv.FormatUint(uint64(ps.Ppid), 10))
	case tid:
		return colorizer.Span(colorizer.Green, strconv.FormatUint(uint64(e.Tid), 10))
	case exe:
		ps := e.PS
		if ps == nil {
			return colorizer.Span(colorizer.Gray, "N/A")
		}
		return colorizer.Span(colorizer.White, ps.Exe)
	case pexe:
		ps := e.PS
		if ps == nil || ps.Parent == nil {
			return colorizer.Span(colorizer.Gray, "N/A")
		}
		return colorizer.Span(colorizer.White, ps.Parent.Exe)
	case cmd:
		ps := e.PS
		if ps == nil {
			return colorizer.Span(colorizer.Gray, "N/A")
		}
		return colorizer.Span(colorizer.White, ps.Cmdline)
	case pcmd:
		ps := e.PS
		if ps == nil || ps.Parent == nil {
			return colorizer.Span(colorizer.Gray, "N/A")
		}
		return colorizer.Span(colorizer.White, ps.Parent.Cmdline)
	case cwd:
		ps := e.PS
		if ps == nil {
			return colorizer.Span(colorizer.Gray, "N/A")
		}
		return colorizer.Span(colorizer.White, ps.Cwd)
	case pproc:
		ps := e.PS
		if ps == nil || ps.Parent == nil {
			return colorizer.Span(colorizer.Gray, "N/A")
		}
		return colorizer.Span(colorizer.Green, ps.Parent.Name)
	case typ:
		return e.Type.color()
	case cat:
		return colorizer.Span(colorizer.Magenta, e.Category().String())
	case parameters:
		return e.Params.Colorize()
	case cstack:
		return fmt.Sprintf("\n%s", e.Callstack.Colorize())
	}

	return ""
}

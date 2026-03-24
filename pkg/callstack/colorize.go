/*
 * Copyright 2021-present by Nedim Sabic Sabic
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

package callstack

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/util/colorizer"
)

// Colorize renders a callstack as a multi-line,
// ANSI-colourised string. It works directly with the typed Frame slice so
// no string parsing is required.
//
// Visual hierarchy per frame (left > right, dim > bright):
//
//	<frame#>  <dim addr>  <muted dir\><module>!<bold symbol>  <dim +offset>
//
// Frame tiers
// ───────────
//
//	kernel   – frame.Addr.InSystemRange()   > magenta
//	unbacked – frame.IsUnbacked()           > red  (highest suspicion)
//	system   – system module                > teal
//	user     – everything else              > amber
//
// Consecutive unresolved frames (kernel-space with no symbol) are collapsed
// into a single dim counter line to avoid flooding the view.
func (s Callstack) Colorize() string {
	if s.IsEmpty() {
		return ""
	}

	// iterate in reverse so the outermost frame comes first
	depth := s.Depth()
	l := s.maxAddrLength()

	var idx int
	var unresolved int
	var b strings.Builder
	b.Grow(depth * 100)

	flushUnresolved := func() {
		if unresolved == 0 {
			return
		}
		line := fmt.Sprintf("  %s %d unresolved %s",
			colorizer.SpanDim("▸"),
			unresolved,
			"frame(s)",
		)
		b.WriteString(colorizer.SpanDim(colorizer.Span(colorizer.Gray, line)))
		b.WriteByte('\n')
		unresolved = 0
	}

	for i := depth - 1; i >= 0; i-- {
		f := s.FrameAt(i)

		// frames in kernel range with no resolved symbol are unresolved so
		// we can collapse them into a counter
		if f.Addr.InSystemRange() && (f.Symbol == "" || f.Symbol == "?") {
			unresolved++
			continue
		}

		flushUnresolved()
		idx++

		// draw gutter
		b.WriteString(colorizer.SpanDim(colorizer.Span(colorizer.Gray, fmt.Sprintf("  %3d  ", idx))))

		// draw address
		addrStr := "0x" + f.Addr.String()
		paddedAddr := addrStr + strings.Repeat(" ", l-len(addrStr))
		b.WriteString(colorizer.SpanDim(colorizer.Span(colorizer.Gray, paddedAddr)))
		b.WriteString("  ")

		// unbacked means execution from anonymous memory which is the highest-
		// suspicion tier, rendered red regardless of address range.
		if f.IsUnbacked() {
			b.WriteString(f.colorizeUnbacked())
			b.WriteByte('\n')
			continue
		}

		clr := f.Provenance().color()

		dir := filepath.Dir(f.Module)
		mod := filepath.Base(f.Module)
		if dir == "." {
			dir = ""
		}
		// module directory
		if dir != "" {
			dir += `\`
			b.WriteString(colorizer.SpanDim(colorizer.Span(clr, dir)))
		}
		// module name
		b.WriteString(colorizer.Span(clr, mod))

		// symbol
		b.WriteString(colorizer.SpanDim("!"))

		sym := f.Symbol
		if sym == "" || sym == "?" {
			sym = "?"
		}
		b.WriteString(colorizer.SpanBold(clr, sym))

		// offset
		if f.Offset != 0 {
			b.WriteString(colorizer.SpanDim(colorizer.Span(colorizer.Gray, fmt.Sprintf("+0x%x", f.Offset))))
		}

		b.WriteByte('\n')
	}

	flushUnresolved()

	return strings.TrimRight(b.String(), "\n")
}

// maxAddrLength measure the widest address string
func (s Callstack) maxAddrLength() int {
	maxw := 0
	for _, f := range s {
		w := len("0x") + len(f.Addr.String())
		maxw = max(maxw, w)
	}
	return maxw
}

// colorizeUnbackedFrame renders the unbacked frame.
func (f Frame) colorizeUnbacked() string {
	var b strings.Builder
	b.WriteString(colorizer.SpanBold(colorizer.Red, "unbacked"))
	b.WriteString(colorizer.SpanDim("!"))
	b.WriteString(colorizer.SpanBold(colorizer.Red, "?"))
	if f.Offset != 0 {
		b.WriteString(colorizer.SpanDim(colorizer.Span(colorizer.Gray, fmt.Sprintf("+0x%x", f.Offset))))
	}
	return b.String()
}

// color return frame provenance color to fill the module
// directory, module base name, and the symbol respectively.
func (p FrameProvenance) color() uint8 {
	switch p {
	case Kernel:
		return colorizer.Magenta
	case System:
		return colorizer.Teal
	default:
		return colorizer.Amber
	}
}

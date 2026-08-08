//go:build linux

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

package callstack

import "strings"

// Callstack is a sequence of stack frames.
type Callstack []Frame

// Frame describes a single stack frame.
type Frame struct {
	PID    uint32
	Addr   uint64
	Symbol string
	Module string
}

func (s *Callstack) Init(n int) {
	*s = make(Callstack, 0, n)
}

func (s *Callstack) PushFrame(f Frame) {
	*s = append(*s, f)
}

func (s *Callstack) FrameAt(i int) Frame {
	if i < 0 || i >= len(*s) {
		return Frame{}
	}
	return (*s)[i]
}

func (s *Callstack) Depth() int { return len(*s) }

func (s *Callstack) IsEmpty() bool { return s.Depth() == 0 }

func (s Callstack) String() string {
	if len(s) == 0 {
		return ""
	}
	parts := make([]string, 0, len(s))
	for _, f := range s {
		if f.Symbol != "" {
			parts = append(parts, f.Symbol)
			continue
		}
		parts = append(parts, f.Module)
	}
	return strings.Join(parts, " < ")
}

// Colorize returns a plain string representation on Linux.
func (s Callstack) Colorize() string { return s.String() }

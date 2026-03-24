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

package event

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/rabbitstack/fibratus/pkg/util/colorizer"
	"github.com/rabbitstack/fibratus/pkg/util/fasttemplate"
)

const (
	// startTag represents the leading tag surrounding field name
	startTag = "{{"
	// endTag represents the trailing tag surrounding field name
	endTag = "}}"

	seq          = ".Seq"
	ts           = ".Timestamp"
	pid          = ".Pid"
	ppid         = ".Ppid"
	pexe         = ".Pexe"
	pcmd         = ".Pcmd"
	pproc        = ".Pname"
	cwd          = ".Cwd"
	exe          = ".Exe"
	cmd          = ".Cmd"
	tid          = ".Tid"
	sid          = ".Sid"
	proc         = ".Process"
	cat          = ".Category"
	desc         = ".Description"
	cpu          = ".CPU"
	typ          = ".Type"
	parameters   = ".Params"
	meta         = ".Meta"
	host         = ".Host"
	pe           = ".PE"
	parsAccessor = ".Params."
	cstack       = ".Callstack"
)

var (
	// tmplRegexp defines the regular expression for parsing template fields.
	tmplRegexp = regexp.MustCompile(`({{2}.*?}{2})`)
	// tmplNormRegepx defines the regular expression for normalizing the template. This basically consists in removing
	// the brackets and trailing/leading spaces from the field name.
	tmplNormRegexp = regexp.MustCompile(`({{2}\s*([A-Za-z.]+)\s*}{2})`)
	// tmplExpandParamsRegexp determines whether Params. fields are expanded
	tmplExpandParamsRegexp = regexp.MustCompile(`{{\s*.Params.\S+}}`)
)

var fields = map[string]bool{
	seq:        true,
	ts:         true,
	pid:        true,
	ppid:       true,
	pexe:       true,
	pcmd:       true,
	pproc:      true,
	cwd:        true,
	exe:        true,
	cmd:        true,
	tid:        true,
	sid:        true,
	proc:       true,
	cat:        true,
	desc:       true,
	cpu:        true,
	typ:        true,
	parameters: true,
	meta:       true,
	host:       true,
	pe:         true,
	cstack:     true,
}

func hintFields() string {
	s := make([]string, 0, len(fields))
	for field := range fields {
		s = append(s, field)
	}
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return strings.Join(s, " ")
}

// Formatter deals with producing event's output that is dictated by the template.
type Formatter struct {
	t               *fasttemplate.Template
	expandParamsDot bool
}

// NewFormatter builds a new instance of event's formatter.
func NewFormatter(template string) (*Formatter, error) {
	// check basic template format and ensure all fields
	// defined in the template are known to us
	flds := tmplRegexp.FindAllStringSubmatch(template, -1)
	if len(flds) == 0 {
		return nil, fmt.Errorf("invalid template format: %q", template)
	}
	if ok, pos := isTemplateBalanced(template); !ok {
		return nil, fmt.Errorf("template syntax error near field #%d: %q", pos, template)
	}

	for i, field := range flds {
		if len(field) > 0 {
			name := sanitize(field[0])
			if strings.HasPrefix(name, parsAccessor) {
				continue
			}
			if name == "" {
				return nil, fmt.Errorf("empty field found at position %d", i+1)
			}
			if _, ok := fields[name]; !ok {
				return nil, fmt.Errorf("%s is not a known field name. Maybe you meant one "+
					"of the following fields: %s", name, hintFields())
			}
		}
	}

	// user might define the tag such as `{{ .Seq }}` or {{ .Seq}}`. We have to make sure
	// inner spaces are removed before building the fast template instance
	norm := normalizeTemplate(template)
	t, err := fasttemplate.NewTemplate(norm, startTag, endTag)
	if err != nil {
		return nil, fmt.Errorf("invalid template format %q: %v", norm, err)
	}

	return &Formatter{
		t:               t,
		expandParamsDot: tmplExpandParamsRegexp.MatchString(norm),
	}, nil
}

// ColorFormatter wraps a Formatter and re-renders each template tag with
// ANSI colour codes before it is substituted into the output string.
//
// It replaces no logic in base formatter template parsing, field validation, and
// normalisation all remain there. ColorFormatter only intercepts the moment
// fasttemplate calls the per-tag writer function, injecting colour at that
// exact boundary.
//
// When colour output is not available (piped stdout, NO_COLOR, dumb terminal,
// pre-Win10) ColorFormatter falls back transparently to the plain formatter.
type ColorFormatter struct {
	f       *Formatter
	enabled bool

	mu       sync.Mutex
	prevTime time.Time // timestamp of the most recently rendered event
}

// NewColorFormatter constructs a ColorFormatter backed by the given Formatter.
// If colour is not available in the current environment the returned value
// behaves identically to the underlying plain Formatter.
func NewColorFormatter(f *Formatter) *ColorFormatter {
	return &ColorFormatter{f: f, enabled: colorizer.IsAnsiEnabled()}
}

// Format renders the event according to the template. Each {{ .Field }} tag is
// substituted with a colour-decorated string when colour output is available,
// or with the plain field value otherwise.
func (f *ColorFormatter) Format(e *Event) []byte {
	if !f.enabled {
		return f.f.Format(e)
	}

	var b bytes.Buffer
	b.WriteString(e.Type.arrow())

	// fasttemplate.Template.ExecuteFuncString calls tagWriter once per tag in
	// document order, passing the bare tag name (e.g. ".Seq", ".Type",
	// ".Params.file_path"). The writer writes the coloured substitution value.
	_, _ = f.f.t.ExecuteFunc(&b, func(w io.Writer, tag string) (int, error) {
		return io.WriteString(w, f.colourTag(tag, e))
	})

	return bytes.TrimRight(b.Bytes(), "\n")
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

	case sid:
		ps := e.PS
		if ps == nil {
			return colorizer.Span(colorizer.Gray, "N/A")
		}
		return colorizer.Span(colorizer.Gray, ps.SID)

	case pproc:
		ps := e.PS
		if ps == nil || ps.Parent == nil {
			return colorizer.Span(colorizer.Gray, "N/A")
		}
		return colorizer.Span(colorizer.Green, ps.Parent.Name)

	case typ:
		return e.Type.color()

	case cat:
		return colorizer.Span(colorizer.Magenta, string(e.Category))

	case parameters:
		return e.Params.Colorize()

	case pe:
		ps := e.PS
		if ps == nil || ps.PE == nil {
			return colorizer.Span(colorizer.Gray, "N/A")
		}
		return colorizer.Span(colorizer.Magenta, ps.PE.String())

	case cstack:
		return fmt.Sprintf("\n%s", e.Callstack.Colorize())
	}

	return ""
}

// colourTimestamp renders the timestamp tag with:
// - date in blue, time in cyan, tz components dim gray
// - a Δt suffix showing the gap from the previous event, colour-coded by
// duration: dim gray (<1ms), brighter gray (1–100ms), amber (>100ms)
func (f *ColorFormatter) colourTimestamp(e *Event) string {
	// compute Δt under the lock, then update prevTime.
	f.mu.Lock()
	var delta time.Duration
	if !f.prevTime.IsZero() {
		delta = max(e.Timestamp.Sub(f.prevTime), 0)
	}
	f.prevTime = e.Timestamp
	f.mu.Unlock()

	// split date and time into two colours so the eye
	// can parse them independently without any delimiter
	// change.
	s := e.Timestamp.String()
	// split into at most 4 parts: date, time, offset, tz-name
	parts := strings.SplitN(s, " ", 4)
	var b strings.Builder
	b.Grow(len(s) + 60)
	for i, p := range parts {
		if i > 0 {
			b.WriteByte(' ')
		}
		switch i {
		case 0: // date
			b.WriteString(colorizer.Span(colorizer.Blue, p))
		case 1: // time with sub-second precision
			b.WriteString(colorizer.Span(colorizer.Cyan, p))
		default: // tz offset, tz name recede visually
			b.WriteString(colorizer.SpanDim(colorizer.Span(colorizer.Gray, p)))
		}
	}

	// Δt suffix only shown after the first event.
	if delta > 0 {
		b.WriteString(colorizer.Span(colorizer.Gray, " · "))
		b.WriteString(f.colourDelta(delta))
	}

	return b.String()
}

// colourDelta formats a duration as a compact human-readable string and
// applies a colour that encodes its significance:
//
// dim gray  — sub-millisecond (high-frequency burst, expected noise)
// gray      — 1ms–100ms (normal inter-event cadence)
// amber     — >100ms (notable gap; something blocked or is infrequent)
func (f *ColorFormatter) colourDelta(d time.Duration) string {
	var s string
	switch {
	case d < time.Millisecond:
		s = fmt.Sprintf("+%dµs", d.Microseconds())
		return colorizer.SpanDim(colorizer.Span(colorizer.Gray, s))
	case d < 100*time.Millisecond:
		s = fmt.Sprintf("+%.2fms", float64(d.Microseconds())/1000)
		return colorizer.Span(colorizer.Gray, s)
	case d < time.Second:
		s = fmt.Sprintf("+%.0fms", float64(d.Microseconds())/1000)
		return colorizer.Span(colorizer.Amber, s)
	default:
		s = fmt.Sprintf("+%.2fs", d.Seconds())
		return colorizer.SpanBold(colorizer.Amber, s)
	}
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '{' || r == '}' || unicode.IsSpace(r) {
			return -1
		}
		return r
	},
		s,
	)
}

func normalizeTemplate(tmpl string) string { return tmplNormRegexp.ReplaceAllString(tmpl, "{{$2}}") }

const expectedBracketsSeq = "{{}}"

// isTemplateBalanced ensures the template string is balanced. This means that each tag in the template
// has its pair of leading/trailing brackets.
func isTemplateBalanced(tmpl string) (bool, int) {
	// drop all but brackets
	s := strings.Map(func(r rune) rune {
		if r == '{' || r == '}' {
			return r
		}
		return -1
	},
		tmpl,
	)
	// partition slice into 4 groups. Each group must follow
	// the correct sequence, otherwise it is an invalid field
	partSize := 4
	partitions := len(s) / partSize
	var i int
	for ; i < partitions; i++ {
		if s[i*partSize:(i+1)*partSize] != expectedBracketsSeq {
			return false, i + 1
		}
	}
	if len(s)%partSize != 0 {
		if s[i*partSize:] != expectedBracketsSeq {
			return false, i + 1
		}
	}
	return true, -1
}

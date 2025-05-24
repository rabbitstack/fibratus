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
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/util/fasttemplate"
	"regexp"
	"sort"
	"strings"
	"unicode"
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
	// tmplExpandKparamsRegexp determines whether Params. fields are expanded
	tmplExpandKparamsRegexp = regexp.MustCompile(`{{\s*.Params.\S+}}`)
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
	t                *fasttemplate.Template
	expandKparamsDot bool
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
		t:                t,
		expandKparamsDot: tmplExpandKparamsRegexp.MatchString(norm),
	}, nil
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

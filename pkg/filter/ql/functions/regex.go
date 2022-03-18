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

package functions

import (
	"regexp"

	log "github.com/sirupsen/logrus"
)

// Regex applies single/multiple regular expressions on the provided string arguments.
type Regex struct {
	rxs map[string]*regexp.Regexp
}

// NewRegex creates a new regex function.
func NewRegex() *Regex {
	return &Regex{rxs: make(map[string]*regexp.Regexp)}
}

func (f Regex) Call(args []interface{}) (interface{}, bool) {
	if len(args) < 2 {
		return false, false
	}
	s := parseString(0, args)

	for _, arg := range args[1:] {
		expr, ok := arg.(string)
		if !ok {
			continue
		}
		rx, compiled := f.rxs[expr]
		if compiled && rx == nil {
			continue
		}
		if !compiled {
			var err error
			rx, err = regexp.Compile(expr)
			if err != nil {
				log.Warnf("invalid regular expression pattern: %v", err)
				// to avoid compiling the regex ad infinitum
				f.rxs[expr] = nil
				continue
			}
			f.rxs[expr] = rx
		}
		if rx.MatchString(s) {
			return true, true
		}
	}

	return false, false
}

func (f Regex) Desc() FunctionDesc {
	desc := FunctionDesc{
		Name: RegexFn,
		Args: []FunctionArgDesc{
			{Keyword: "string", Types: []ArgType{Field, String, Func}, Required: true},
			{Keyword: "regexp", Types: []ArgType{String}, Required: true},
		},
	}
	offset := len(desc.Args)
	// add optional regular expression patterns
	for i := offset; i < maxArgs; i++ {
		desc.Args = append(desc.Args, FunctionArgDesc{Keyword: "regexp", Types: []ArgType{String}})
	}
	return desc
}

func (f Regex) Name() Fn { return RegexFn }

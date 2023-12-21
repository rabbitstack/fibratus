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
	"fmt"
	"strings"
)

// IndexPosition is the type alias for the string position search order
type IndexPosition uint8

const (
	UnknownIndex IndexPosition = iota
	FirstIndex                 // Index
	AnyIndex                   // IndexAny
	LastIndex                  // LastIndex
	LastAnyIndex               // LastIndexAny
)

var indexMappings = map[string]IndexPosition{
	"first":   FirstIndex,
	"any":     AnyIndex,
	"last":    LastIndex,
	"lastany": LastAnyIndex,
}

func indexFromString(s string) IndexPosition { return indexMappings[s] }

// IndexOf returns the index of the instance of substring in a given string
// depending on the provided search order.
type IndexOf struct{}

func (f IndexOf) Call(args []interface{}) (interface{}, bool) {
	if len(args) < 2 {
		return false, false
	}
	str := parseString(0, args)
	substr := parseString(1, args)
	if len(args) == 2 {
		return strings.Index(str, substr), true
	}
	// index search order
	switch indexFromString(parseString(2, args)) {
	case FirstIndex:
		return strings.Index(str, substr), true
	case AnyIndex:
		return strings.IndexAny(str, substr), true
	case LastIndex:
		return strings.LastIndex(str, substr), true
	case LastAnyIndex:
		return strings.LastIndexAny(str, substr), true
	default:
		return false, false
	}
}

func (f IndexOf) Desc() FunctionDesc {
	desc := FunctionDesc{
		Name: IndexOfFn,
		Args: []FunctionArgDesc{
			{Keyword: "string", Types: []ArgType{Field, Func}, Required: true},
			{Keyword: "substr", Types: []ArgType{String, Func}, Required: true},
			{Keyword: "index", Types: []ArgType{String}},
		},
		ArgsValidationFunc: func(args []string) error {
			if len(args) == 2 {
				return nil
			}
			if len(args) == 3 && indexFromString(args[2]) == UnknownIndex {
				return fmt.Errorf("%s is not a valid index search order. Available options are: first,any,last,lastany", args[2])
			}
			return nil
		},
	}
	return desc
}

func (f IndexOf) Name() Fn { return IndexOfFn }

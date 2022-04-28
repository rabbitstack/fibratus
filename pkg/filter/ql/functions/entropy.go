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
	"math"
)

const (
	shannonAlgo = "shannon"
)

// Entropy measures the string entropy
type Entropy struct{}

func (f Entropy) Call(args []interface{}) (interface{}, bool) {
	if len(args) < 1 {
		return false, false
	}
	s := parseString(0, args)
	if len(args) == 1 {
		return shannon(s), true
	}
	algo := parseString(1, args)
	switch algo {
	case shannonAlgo:
		return shannon(s), true
	default:
		return false, false
	}
}

func (f Entropy) Desc() FunctionDesc {
	desc := FunctionDesc{
		Name: LengthFn,
		Args: []FunctionArgDesc{
			{Keyword: "string", Types: []ArgType{Field, Func}, Required: true},
			{Keyword: "algo", Types: []ArgType{String}},
		},
		ArgsValidationFunc: func(args []string) error {
			if len(args) == 1 {
				return nil
			}
			if len(args) > 1 && args[1] != shannonAlgo {
				return fmt.Errorf("unsupported entropy algorithm: %s. Availiable algorithms: shannon", args[1])
			}
			return nil
		},
	}
	return desc
}

func (f Entropy) Name() Fn { return EntropyFn }

// shannon measures the Shannon entropy of a string.
func shannon(value string) int {
	frq := make(map[rune]float64)

	//get frequency of characters
	for _, i := range value {
		frq[i]++
	}

	var sum float64

	for _, v := range frq {
		f := v / float64(len(value))
		sum += f * math.Log2(f)
	}

	return int(math.Ceil(sum*-1)) * len(value)
}

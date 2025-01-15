//go:build !yara
// +build !yara

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
	kerrors "github.com/rabbitstack/fibratus/pkg/errors"
)

// Yara unsupported function
type Yara struct{}

func (f Yara) Call(args []interface{}) (interface{}, bool) { return false, false }

func (f Yara) Desc() FunctionDesc {
	desc := FunctionDesc{
		Name: YaraFn,
		Args: []FunctionArgDesc{
			{Keyword: "pid|file|bytes", Types: []ArgType{Field, BoundField, Func, String, Number}, Required: true},
			{Keyword: "rules", Types: []ArgType{Field, BoundField, Func, String}, Required: true},
			{Keyword: "vars", Types: []ArgType{Field, BoundField, Func, String}},
		},
		ArgsValidationFunc: func(args []string) error {
			return fmt.Errorf("yara function is not supported. %w", kerrors.ErrFeatureUnsupported("yara"))
		},
	}
	return desc
}

func (f Yara) Name() Fn { return YaraFn }

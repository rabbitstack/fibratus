/*
 * Copyright 2020-2021 by Nedim Sabic Sabic
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
	"crypto/md5"
	"encoding/hex"
)

// MD5 computes the MD5 hash of the given value.
type MD5 struct{}

func (f MD5) Call(args []interface{}) (interface{}, bool) {
	if len(args) != 1 {
		return false, false
	}

	var data []byte
	switch v := args[0].(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	}

	if data == nil {
		return false, false
	}

	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:]), true
}

func (f MD5) Desc() FunctionDesc {
	return FunctionDesc{
		Name: MD5Fn,
		Args: []FunctionArgDesc{
			{Keyword: "data", Types: []ArgType{Field, String, BoundField, Func}, Required: true},
		},
	}
}

func (f MD5) Name() Fn { return MD5Fn }

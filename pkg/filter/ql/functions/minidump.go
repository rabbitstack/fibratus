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
	"encoding/binary"
	"io"
	"os"
)

// The 4-byte magic number at the start of a minidump file
const minidumpSignature = 1347241037

// IsMinidump determines if the specified file contains the minidump signature.
type IsMinidump struct{}

func (f IsMinidump) Call(args []interface{}) (interface{}, bool) {
	if len(args) < 1 {
		return false, false
	}
	path := args[0].(string)

	file, err := os.Open(path)
	if err != nil {
		return false, true
	}
	defer file.Close()

	var header [4]byte
	_, err = io.ReadFull(file, header[:])
	if err != nil {
		return false, true
	}
	isMinidumpSignature := binary.LittleEndian.Uint32(header[:]) == minidumpSignature
	return isMinidumpSignature, true
}

func (f IsMinidump) Desc() FunctionDesc {
	desc := FunctionDesc{
		Name: IsMinidumpFn,
		Args: []FunctionArgDesc{
			{Keyword: "path", Types: []ArgType{String, Field, Func}, Required: true},
		},
	}
	return desc
}

func (f IsMinidump) Name() Fn { return IsMinidumpFn }

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

package eval

import (
	"encoding/binary"
	"path/filepath"
	"strings"
	"time"

	"github.com/rabbitstack/fibratus/pkg/compiler/functions"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"golang.org/x/sys/windows/registry"
)

func newSysFunction(fn functions.Fn, args []Evaluator) Evaluator {
	switch fn {
	case functions.GetRegValueFn:
		return &GetRegValueEvaluator{EvaluatorBase: EvaluatorBase{Expensive: true}, Path: args[0]}
	case functions.IsMinidumpFn:
		return &IsMinidumpEvaluator{EvaluatorBase: EvaluatorBase{Expensive: true}, Path: args[0]}
	}
	return nil
}

// GetRegValueEvaluator evaluates the get_reg_value function, which retrieves the
// content of the registry value. The path starts with the root key, e.g.
// HKLM\SOFTWARE\Vendor\Value. There is no value if the value can't be read.
type GetRegValueEvaluator struct {
	EvaluatorBase
	Path Evaluator
}

func (e *GetRegValueEvaluator) Eval(ctx *EvalCtx) any {
	path := strArg(ctx, e.Path)
	n := strings.Index(path, "\\")
	if n <= 0 {
		return nil
	}
	rootKey := path[:n]
	subkey, value := filepath.Split(path[n+1:])
	key, err := registry.OpenKey(keyFromString(rootKey), subkey, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer key.Close()
	_, typ, err := key.GetValue(value, make([]byte, 0))
	if err != nil {
		return nil
	}
	var val any
	switch typ {
	case registry.SZ, registry.EXPAND_SZ:
		val, _, err = key.GetStringValue(value)
	case registry.MULTI_SZ:
		val, _, err = key.GetStringsValue(value)
	case registry.DWORD:
		val, _, err = key.GetIntegerValue(value)
		if err == nil {
			val = uint32(val.(uint64))
		}
	case registry.QWORD:
		val, _, err = key.GetIntegerValue(value)
	case registry.BINARY:
		val, _, err = key.GetBinaryValue(value)
	}
	if err != nil {
		return nil
	}
	return val
}

func keyFromString(k string) registry.Key {
	switch strings.ToUpper(k) {
	case "HKEY_LOCAL_MACHINE", "HKLM":
		return registry.LOCAL_MACHINE
	case "HKEY_CURRENT_USER", "HKCU":
		return registry.CURRENT_USER
	case "HKEY_USERS", "HKU":
		return registry.USERS
	case "HKEY_CLASSES_ROOT", "HKCR":
		return registry.CLASSES_ROOT
	case "HKEY_CURRENT_CONFIG", "HKCC":
		return registry.CURRENT_CONFIG
	case "HKEY_PERFORMANCE_DATA", "HKPD":
		return registry.PERFORMANCE_DATA
	default:
		return registry.Key(0)
	}
}

const minidumpSignature = 1347241037

// IsMinidumpEvaluator evaluates the is_minidump function, which tells whether the file
// starts with the minidump signature. There is no value if the file can't be read.
type IsMinidumpEvaluator struct {
	EvaluatorBase
	Path Evaluator
}

func (e *IsMinidumpEvaluator) Eval(ctx *EvalCtx) any {
	b, err := sys.ReadFile(strArg(ctx, e.Path), 4, time.Second)
	if err != nil || len(b) < 4 {
		return nil
	}
	return binary.LittleEndian.Uint32(b[:]) == minidumpSignature
}

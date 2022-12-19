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
	"golang.org/x/sys/windows/registry"
	"path/filepath"
	"strings"
)

// GetRegValue retrieves the content of the registry value.
type GetRegValue struct{}

func (f GetRegValue) Call(args []interface{}) (interface{}, bool) {
	if len(args) < 1 {
		return false, false
	}
	path := parseString(0, args)
	n := strings.Index(path, "\\")
	if n > 0 {
		rootKey := path[:n]
		subkey, value := filepath.Split(path[:n])
		key, err := registry.OpenKey(keyFromString(rootKey), subkey, registry.QUERY_VALUE)
		if err != nil {
			return nil, true
		}
		defer key.Close()
		b := make([]byte, 0)
		_, typ, err := key.GetValue(value, b)
		if err != nil {
			return nil, true
		}
		var val interface{}
		switch typ {
		case registry.SZ, registry.EXPAND_SZ:
			val, _, err = key.GetStringValue(value)
		case registry.MULTI_SZ:
			val, _, err = key.GetStringsValue(value)
		case registry.DWORD, registry.QWORD:
			val, _, err = key.GetIntegerValue(value)
		case registry.BINARY:
			val, _, err = key.GetBinaryValue(value)
		}
		if err != nil {
			return nil, true
		}
		return val, true
	}
	return nil, true
}

func (f GetRegValue) Desc() FunctionDesc {
	desc := FunctionDesc{
		Name: GetRegValueFn,
		Args: []FunctionArgDesc{
			{Keyword: "path", Types: []ArgType{Field, String, Func}, Required: true},
		},
	}
	return desc
}

func (f GetRegValue) Name() Fn { return GetRegValueFn }

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
	}
	return registry.Key(-1)
}

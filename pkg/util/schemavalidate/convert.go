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

package schemavalidate

import (
	"fmt"
	"reflect"
)

// NormalizeKeys returns a deep copy of v in which every map has string keys,
// so the result can be handed to a JSON schema validator.
//
// This is needed because YAML decoders (gopkg.in/yaml.v2, viper's older
// backends, ...) produce map[interface{}]interface{} for nested mappings,
// which neither encoding/json nor JSON schema validators understand.
//
// Handled containers: map[string]interface{}, map[interface{}]interface{},
// []interface{}, and, through reflection, any other map, slice, array or
// pointer whose elements are (or contain) such values, e.g.
// []map[interface{}]interface{}. Structs are not traversed; they are returned
// as-is and left to encoding/json. []byte is also returned as-is.
//
// Nil maps and slices become nil (JSON null); empty, non-nil slices stay empty
// (JSON []). The input is never modified.
//
// If a map has a key that is not a string, a *KeyError is returned.
func NormalizeKeys(v interface{}) (interface{}, error) {
	return normalize(v, "")
}

func normalize(v interface{}, path string) (interface{}, error) {
	switch t := v.(type) {
	case nil:
		return nil, nil
	case map[string]interface{}:
		if t == nil {
			return nil, nil
		}
		out := make(map[string]interface{}, len(t))
		for k, e := range t {
			c, err := normalize(e, joinPath(path, k))
			if err != nil {
				return nil, err
			}
			out[k] = c
		}
		return out, nil
	case map[interface{}]interface{}:
		if t == nil {
			return nil, nil
		}
		out := make(map[string]interface{}, len(t))
		for k, e := range t {
			s, ok := k.(string)
			if !ok {
				return nil, &KeyError{Path: path, Key: k}
			}
			c, err := normalize(e, joinPath(path, s))
			if err != nil {
				return nil, err
			}
			out[s] = c
		}
		return out, nil
	case []interface{}:
		if t == nil {
			return nil, nil
		}
		out := make([]interface{}, len(t))
		for i, e := range t {
			c, err := normalize(e, indexPath(path, i))
			if err != nil {
				return nil, err
			}
			out[i] = c
		}
		return out, nil
	}
	return normalizeReflect(v, path)
}

// normalizeReflect is the slow path for container types that are not covered
// by the type switch in normalize.
func normalizeReflect(v interface{}, path string) (interface{}, error) {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Ptr, reflect.Interface:
		if rv.IsNil() {
			return nil, nil
		}
		return normalize(rv.Elem().Interface(), path)

	case reflect.Map:
		if rv.IsNil() {
			return nil, nil
		}
		out := make(map[string]interface{}, rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			k := iter.Key()
			for k.Kind() == reflect.Interface && !k.IsNil() {
				k = k.Elem()
			}
			if k.Kind() != reflect.String {
				return nil, &KeyError{Path: path, Key: iter.Key().Interface()}
			}
			ks := k.String()
			c, err := normalize(iter.Value().Interface(), joinPath(path, ks))
			if err != nil {
				return nil, err
			}
			out[ks] = c
		}
		return out, nil

	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice {
			if rv.IsNil() {
				return nil, nil
			}
			// encoding/json renders []byte as a base64 string.
			if rv.Type().Elem().Kind() == reflect.Uint8 {
				return v, nil
			}
		}
		out := make([]interface{}, rv.Len())
		for i := range out {
			c, err := normalize(rv.Index(i).Interface(), indexPath(path, i))
			if err != nil {
				return nil, err
			}
			out[i] = c
		}
		return out, nil
	}
	return v, nil
}

func joinPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func indexPath(path string, i int) string {
	return fmt.Sprintf("%s[%d]", path, i)
}

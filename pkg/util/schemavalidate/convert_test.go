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
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestNormalizeKeys(t *testing.T) {
	tests := []struct {
		name string
		in   interface{}
		want interface{}
	}{
		{"nil", nil, nil},
		{"scalar", 42, 42},
		{"string map", map[string]interface{}{"a": 1}, map[string]interface{}{"a": 1}},
		{
			"yaml style nested",
			map[interface{}]interface{}{
				"server": map[interface{}]interface{}{"port": 8080},
			},
			map[string]interface{}{
				"server": map[string]interface{}{"port": 8080},
			},
		},
		{
			"list of yaml maps",
			[]interface{}{map[interface{}]interface{}{"k": "v"}},
			[]interface{}{map[string]interface{}{"k": "v"}},
		},
		{
			"typed slice of yaml maps",
			[]map[interface{}]interface{}{{"k": "v"}},
			[]interface{}{map[string]interface{}{"k": "v"}},
		},
		{
			"typed map of any value",
			map[string][]interface{}{"xs": {map[interface{}]interface{}{"a": 1}}},
			map[string]interface{}{"xs": []interface{}{map[string]interface{}{"a": 1}}},
		},
		{"nil map", map[string]interface{}(nil), nil},
		{"empty slice stays empty", []interface{}{}, []interface{}{}},
		{"bytes untouched", []byte("hi"), []byte("hi")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeKeys(tt.in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %#v, want %#v", got, tt.want)
			}
			if _, err := json.Marshal(got); err != nil {
				t.Fatalf("result is not JSON-encodable: %v", err)
			}
		})
	}
}

func TestNormalizeKeysDoesNotMutateInput(t *testing.T) {
	in := map[interface{}]interface{}{"a": map[interface{}]interface{}{"b": 1}}
	if _, err := NormalizeKeys(in); err != nil {
		t.Fatal(err)
	}
	if _, ok := in["a"].(map[interface{}]interface{}); !ok {
		t.Fatal("input was modified")
	}
}

func TestNormalizeKeysNonStringKey(t *testing.T) {
	tests := []struct {
		name     string
		in       interface{}
		wantPath string
		wantKey  interface{}
	}{
		{"top level", map[interface{}]interface{}{1: "x"}, "", 1},
		{
			"nested with list index",
			map[interface{}]interface{}{
				"servers": []interface{}{
					map[interface{}]interface{}{"ok": 1},
					map[interface{}]interface{}{"tags": map[interface{}]interface{}{true: "y"}},
				},
			},
			"servers[1].tags", true,
		},
		{"typed map", map[int]string{7: "x"}, "", 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NormalizeKeys(tt.in)
			var ke *KeyError
			if !errors.As(err, &ke) {
				t.Fatalf("want *KeyError, got %v", err)
			}
			if ke.Path != tt.wantPath || !reflect.DeepEqual(ke.Key, tt.wantKey) {
				t.Fatalf("got path=%q key=%#v, want path=%q key=%#v", ke.Path, ke.Key, tt.wantPath, tt.wantKey)
			}
		})
	}
}

func TestKeyErrorMessage(t *testing.T) {
	if got := (&KeyError{Key: 1}).Error(); got != "non-string key at top level: 1" {
		t.Fatalf("got %q", got)
	}
	if got := (&KeyError{Path: "a.b", Key: 1}).Error(); got != "non-string key in a.b: 1" {
		t.Fatalf("got %q", got)
	}
}

func TestValidationErrorUnwrap(t *testing.T) {
	fe := &FieldError{Field: "port", Type: "invalid_type", Description: "Invalid type"}
	ve := &ValidationError{Errors: []error{fe, &FieldError{Field: "(root)", Description: "x is required"}}}
	var got *FieldError
	if !errors.As(ve, &got) || got != fe {
		t.Fatal("errors.As should reach the first FieldError")
	}
	if ve.Error() == "" {
		t.Fatal("empty message")
	}
}

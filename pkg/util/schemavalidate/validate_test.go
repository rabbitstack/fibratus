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
	"errors"
	"testing"
)

const testSchema = `{
  "type": "object",
  "required": ["server"],
  "properties": {
    "server": {
      "type": "object",
      "required": ["port"],
      "properties": {
        "port": {"type": "integer", "minimum": 1, "maximum": 65535},
        "tags": {"type": "array", "items": {"type": "string"}}
      }
    }
  }
}`

func TestValidate(t *testing.T) {
	v, err := NewFromString(testSchema)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("valid yaml-style doc", func(t *testing.T) {
		doc := map[interface{}]interface{}{
			"server": map[interface{}]interface{}{"port": 8080, "tags": []interface{}{"a", "b"}},
		}
		if err := v.Validate(doc); err != nil {
			t.Fatalf("unexpected: %v", err)
		}
	})

	t.Run("valid string-key doc", func(t *testing.T) {
		doc := map[string]interface{}{"server": map[string]interface{}{"port": 80}}
		if err := v.Validate(doc); err != nil {
			t.Fatalf("unexpected: %v", err)
		}
	})

	t.Run("collects all violations", func(t *testing.T) {
		doc := map[interface{}]interface{}{
			"server": map[interface{}]interface{}{"port": 70000, "tags": []interface{}{1}},
		}
		err := v.Validate(doc)
		var ve *ValidationError
		if !errors.As(err, &ve) {
			t.Fatalf("want *ValidationError, got %v", err)
		}
		if len(ve.Errors) != 2 {
			t.Fatalf("want 2 violations, got %d: %v", len(ve.Errors), ve)
		}
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Field == "" || fe.Type == "" {
			t.Fatalf("FieldError not populated: %#v", fe)
		}
	})

	t.Run("missing required", func(t *testing.T) {
		err := v.Validate(map[string]interface{}{})
		var ve *ValidationError
		if !errors.As(err, &ve) {
			t.Fatalf("want *ValidationError, got %v", err)
		}
	})

	t.Run("non-string key is not a validation error", func(t *testing.T) {
		err := v.Validate(map[interface{}]interface{}{1: "x"})
		var ke *KeyError
		var ve *ValidationError
		if !errors.As(err, &ke) || errors.As(err, &ve) {
			t.Fatalf("want *KeyError only, got %v", err)
		}
	})
}

func TestValidateJSON(t *testing.T) {
	v, err := NewFromString(testSchema)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.ValidateJSON([]byte(`{"server":{"port":1}}`)); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	var ve *ValidationError
	if err := v.ValidateJSON([]byte(`{"server":{}}`)); !errors.As(err, &ve) {
		t.Fatalf("want *ValidationError, got %v", err)
	}
}

func TestNewBadSchema(t *testing.T) {
	if _, err := NewFromString(`{"type": 12}`); err == nil {
		t.Fatal("expected compile error")
	}
	if err := Validate(`not json`, nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestOneShotValidate(t *testing.T) {
	if err := Validate(testSchema, map[string]interface{}{"server": map[string]interface{}{"port": 1}}); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

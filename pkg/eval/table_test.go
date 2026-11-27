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
	"testing"

	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/stretchr/testify/assert"
)

// unserved are the declared fields that no source ever served. They always
// evaluate to the default value of their type.
var unserved = map[fields.Field]bool{
	fields.PsDTB:       true,
	fields.PsParentDTB: true,
}

// TestEveryDeclaredFieldIsServed checks the switches are complete on the
// platform the test runs on: all the declared fields have an evaluator, so a
// field that is added to the declarations can't be forgotten.
func TestEveryDeclaredFieldIsServed(t *testing.T) {
	for _, def := range fields.Get() {
		if unserved[def.Field] {
			assert.False(t, hasEvaluator(def.Field), "%s is listed as unserved", def.Field)
			continue
		}
		assert.True(t, hasEvaluator(def.Field), "%s is declared, but has no evaluator", def.Field)
	}
}

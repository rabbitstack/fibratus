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

package functions

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCatalogDescribesEveryFunction(t *testing.T) {
	for fn := CIDRContainsFn; fn <= CountFn; fn++ {
		desc, ok := Lookup(fn.String())
		if !ok {
			// the functions that are not available on the platform
			assert.Contains(t, []Fn{GetRegValueFn, IsMinidumpFn, YaraFn}, fn, fn.String())
			continue
		}
		assert.Equal(t, fn, desc.Name, "the name of the signature of %s", fn)
		assert.NotEqual(t, "UNDEFINED", fn.String())
	}
}

func TestLookupAndParseIgnoreCase(t *testing.T) {
	for _, name := range []string{"lower", "Lower", "LOWER"} {
		desc, ok := Lookup(name)
		require.True(t, ok)
		assert.Equal(t, LowerFn, desc.Name)
	}
	fn, ok := Parse("symlink")
	assert.True(t, ok)
	assert.Equal(t, SymlinkFn, fn)

	_, ok = Lookup("nope")
	assert.False(t, ok)
	_, ok = Parse("nope")
	assert.False(t, ok)
}

func TestNames(t *testing.T) {
	names := Names()
	assert.Contains(t, names, "LTRIM")
	assert.Contains(t, names, "RTRIM")
	assert.Contains(t, names, "ENTROPY")
	assert.Contains(t, names, "SYMLINK")
	assert.Contains(t, names, "FOREACH")
	assert.True(t, sortedStrings(names))
}

func sortedStrings(s []string) bool {
	for i := 1; i < len(s); i++ {
		if strings.Compare(s[i-1], s[i]) > 0 {
			return false
		}
	}
	return true
}

func TestSignatures(t *testing.T) {
	var tests = []struct {
		fn       string
		required int
		args     int
	}{
		{"cidr_contains", 2, maxArgs},
		{"md5", 1, 1},
		{"lower", 1, 1},
		{"ltrim", 2, 2},
		{"rtrim", 2, 2},
		{"foreach", 3, 13},
	}
	for _, tt := range tests {
		desc, ok := Lookup(tt.fn)
		require.True(t, ok, tt.fn)
		assert.Equal(t, tt.required, desc.RequiredArgs(), tt.fn)
		assert.Len(t, desc.Args, tt.args, tt.fn)
	}
}

func TestIndexOfValidation(t *testing.T) {
	desc, _ := Lookup("indexof")
	require.NotNil(t, desc.ArgsValidationFunc)
	assert.NoError(t, desc.ArgsValidationFunc([]string{"a", "b"}))
	assert.NoError(t, desc.ArgsValidationFunc([]string{"a", "b", "lastany"}))
	assert.Error(t, desc.ArgsValidationFunc([]string{"a", "b", "middle"}))
}

func TestForeachValidation(t *testing.T) {
	desc, _ := Lookup("foreach")
	require.NotNil(t, desc.ArgsValidationFunc)
	assert.Error(t, desc.ArgsValidationFunc([]string{"ps._modules", "$ps", "$ps.path = 'a'"}), "reserved variable")
	assert.Error(t, desc.ArgsValidationFunc([]string{"ps._modules", "$m", "$x.path = 'a'"}), "undeclared variable")
	assert.Error(t, desc.ArgsValidationFunc([]string{"ps._modules", "$m", "evt.name = 'a'"}), "unused variable")
}

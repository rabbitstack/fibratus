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
	"errors"
	"expvar"
	"fmt"
	"io/fs"
	"testing"

	errs "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func resetAccessorErrors() {
	accessorErrorKeysMu.Lock()
	defer accessorErrorKeysMu.Unlock()
	accessorErrorKeys = make(map[string]struct{})
	accessorErrors.Init()
}

func TestNormalizeAccessorError(t *testing.T) {
	var tests = []struct {
		name string
		err  error
		key  string
	}{
		{"param not found pointer", &errs.ErrParamNotFound{Name: "cmdline"}, "parameter not found"},
		{"param not found value", fmt.Errorf("wrapped: %w", errs.ErrParamNotFound{Name: "exe"}), "parameter not found"},
		{"path error", &fs.PathError{Op: "open", Path: `C:\Users\bob\a.dll`, Err: errors.New("access denied")}, "open: access denied"},
		{"wrapped path error", fmt.Errorf("pe: %w", &fs.PathError{Op: "open", Path: `C:\x.dll`, Err: errors.New("access denied")}), "open: access denied"},
		{"plain error", errors.New("process state is nil"), "process state is nil"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.key, normalizeAccessorError(tt.err))
		})
	}
}

func TestCountAccessorErrorIsBounded(t *testing.T) {
	resetAccessorErrors()
	t.Cleanup(resetAccessorErrors)

	// errors that differ only by the path collapse into a single key
	for i := 0; i < 1000; i++ {
		countAccessorError(&fs.PathError{Op: "open", Path: fmt.Sprintf(`C:\tmp\%d.dll`, i), Err: errors.New("not found")})
	}
	n := 0
	accessorErrors.Do(func(kv expvar.KeyValue) { n++ })
	assert.Equal(t, 1, n)

	// arbitrary error messages can't grow the map past the limit
	for i := 0; i < 5*maxAccessorErrorKeys; i++ {
		countAccessorError(fmt.Errorf("unexpected failure %d", i))
	}
	n = 0
	accessorErrors.Do(func(kv expvar.KeyValue) { n++ })
	assert.LessOrEqual(t, n, maxAccessorErrorKeys+1)
	assert.NotNil(t, accessorErrors.Get(otherAccessorErrors))
}

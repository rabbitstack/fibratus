/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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

package cpython

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNewModule(t *testing.T) {
	require.NoError(t, Initialize())
	defer Finalize()
	AddPythonPath("_fixtures/")
	mod, err := NewModule("top_hives_io")
	require.NoError(t, err)
	require.NotNil(t, mod)
}

func TestModuleRegisterFn(t *testing.T) {
	require.NoError(t, Initialize())
	defer Finalize()
	AddPythonPath("_fixtures/")
	mod, err := NewModule("top_hives_io")
	require.NoError(t, err)
	require.NotNil(t, mod)

	f := func() uintptr { return 0 }

	err = mod.RegisterFn("set_interval", f, MethVarArgs)
	require.NoError(t, err)

	fn, err := mod.GetAttrString("set_interval")
	require.NoError(t, err)
	require.False(t, fn.IsNull())
	require.True(t, fn.IsCallable())
	fn.Call()

	fn, err = mod.GetAttrString("sum")
	require.NoError(t, err)
	require.False(t, fn.IsNull())
	require.True(t, fn.IsCallable())
	r := fn.Call(PyUnicodeFromString("test"))
	require.False(t, r.IsNull())
}

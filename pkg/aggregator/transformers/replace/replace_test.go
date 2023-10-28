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

package replace

import (
	"github.com/rabbitstack/fibratus/pkg/aggregator/transformers"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestTransform(t *testing.T) {
	kevt := &kevent.Kevent{
		Type: ktypes.RegCreateKey,
		Tid:  2484,
		PID:  859,
		Kparams: kevent.Kparams{
			kparams.RegKeyName:   {Name: kparams.RegKeyName, Type: kparams.UnicodeString, Value: `HKEY_LOCAL_MACHINE\SYSTEM\Setup\Pid`},
			kparams.RegKeyHandle: {Name: kparams.RegKeyHandle, Type: kparams.Address, Value: uint64(18446666033449935464)},
		},
	}

	transf, err := transformers.Load(transformers.Config{Type: transformers.Replace, Transformer: Config{Replacements: []Replacement{{Kpar: "key_name", Old: "HKEY_LOCAL_MACHINE", New: "HKLM"}}}})
	require.NoError(t, err)

	require.NoError(t, transf.Transform(kevt))

	keyName, _ := kevt.Kparams.GetString(kparams.RegKeyName)

	assert.Equal(t, `HKLM\SYSTEM\Setup\Pid`, keyName)
}

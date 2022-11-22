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

package processors

import (
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRegistryInterceptor(t *testing.T) {
	r := newRegistryInterceptor(nil)

	_, _, err := r.Intercept(&kevent.Kevent{
		Type: ktypes.RegKCBRundown,
		Tid:  2484,
		PID:  859,
		Kparams: kevent.Kparams{
			kparams.RegKeyName:   {Name: kparams.RegKeyName, Type: kparams.UnicodeString, Value: `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\bthserv\Parameters`},
			kparams.RegKeyHandle: {Name: kparams.RegKeyHandle, Type: kparams.HexInt64, Value: kparams.NewHex(uint64(18446666033549154696))},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), kcbCount.Value())

	_, _, err = r.Intercept(&kevent.Kevent{
		Type: ktypes.RegCreateKCB,
		Tid:  1484,
		PID:  259,
		Kparams: kevent.Kparams{
			kparams.RegKeyName:   {Name: kparams.RegKeyName, Type: kparams.UnicodeString, Value: `\REGISTRY\MACHINE\SYSTEM\Setup`},
			kparams.RegKeyHandle: {Name: kparams.RegKeyHandle, Type: kparams.HexInt64, Value: kparams.NewHex(uint64(18446666033449935464))},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(2), kcbCount.Value())

	kevt := &kevent.Kevent{
		Type: ktypes.RegCreateKey,
		Tid:  2484,
		PID:  859,
		Kparams: kevent.Kparams{
			kparams.RegKeyName:   {Name: kparams.RegKeyName, Type: kparams.UnicodeString, Value: `Pid`},
			kparams.RegKeyHandle: {Name: kparams.RegKeyHandle, Type: kparams.HexInt64, Value: kparams.NewHex(uint64(18446666033449935464))},
		},
	}
	_, _, err = r.Intercept(kevt)
	require.NoError(t, err)

	keyName, err := kevt.Kparams.GetString(kparams.RegKeyName)
	require.NoError(t, err)
	assert.Equal(t, `HKEY_LOCAL_MACHINE\SYSTEM\Setup\Pid`, keyName)
}

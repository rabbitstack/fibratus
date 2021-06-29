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

package kparams

import (
	"github.com/stretchr/testify/assert"

	"testing"
)

func TestNewHex(t *testing.T) {
	hex := NewHex(uint32(7264))
	assert.Equal(t, Hex("1c60"), hex)
	assert.Equal(t, uint32(7264), hex.Uint32())

	hex = NewHex(uint32(4294967295))
	assert.Equal(t, Hex("ffffffff"), hex)

	hex = NewHex(uint64(18446744073709551615))
	assert.Equal(t, Hex("ffffffffffffffff"), hex)
	assert.Equal(t, uint64(18446744073709551615), hex.Uint64())
}

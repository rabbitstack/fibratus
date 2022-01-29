/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLength(t *testing.T) {
	call := Length{}
	res, _ := call.Call([]interface{}{"hello"})
	assert.Equal(t, 5, res)

	res1, _ := call.Call([]interface{}{"こんにちは"})
	assert.Equal(t, 5, res1)

	res2, _ := call.Call([]interface{}{[]string{"hello", "world"}})
	assert.Equal(t, 2, res2)
}

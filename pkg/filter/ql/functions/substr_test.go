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

func TestSubstr(t *testing.T) {
	call := Substr{}
	res, _ := call.Call([]interface{}{"Hello", 0, 4})
	assert.Equal(t, "Hell", res)

	res1, _ := call.Call([]interface{}{"Hello World!", 0, 50})
	assert.Equal(t, "Hello World!", res1)

	res2, _ := call.Call([]interface{}{"Hello World!", 4, -1})
	assert.Equal(t, "Hello World!", res2)

	res3, _ := call.Call([]interface{}{"Hello World!", -1, 10})
	assert.Equal(t, "Hello World!", res3)

	res4, _ := call.Call([]interface{}{"Hello World!", 6, 7})
	assert.Equal(t, "W", res4)
}

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

package ql

import (
	"github.com/magiconair/properties/assert"
	"testing"
)

func TestParseError(t *testing.T) {
	err := newParseError("[", []string{"("}, 10, "ps.name in ['svchost.exe', 'cmd.exe')")
	expected := "\nps.name in ['svchost.exe', 'cmd.exe')\n" +
		"           ^ expected ("
	assert.Equal(t, expected, err.Error())
}

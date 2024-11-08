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

package eventlog

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/windows"
	"testing"
)

func TestEventID(t *testing.T) {
	var tests = []struct {
		eid      uint32
		expected uint32
	}{
		{
			EventID(windows.EVENTLOG_INFORMATION_TYPE, 3191),
			0x20000c77,
		},
		{
			EventID(windows.EVENTLOG_WARNING_TYPE, 3191),
			0x40000c77,
		},
		{
			EventID(windows.EVENTLOG_ERROR_TYPE, 3191),
			0x60000c77,
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d", tt.expected), func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.eid)
		})
	}
}

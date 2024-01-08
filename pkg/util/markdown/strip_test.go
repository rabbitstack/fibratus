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

package markdown

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestStrip(t *testing.T) {
	md := `Detected an attempt by mimikatz.exe process to access and read
         the memory of the **Local Security And Authority Subsystem Service**
         and subsequently write the _C:\\dump.dmp_ dump file to the disk device`
	expected := `Detected an attempt by mimikatz.exe process to access and read
         the memory of the Local Security And Authority Subsystem Service
         and subsequently write the C:\\dump.dmp dump file to the disk device`
	assert.Equal(t, expected, Strip(md))
}

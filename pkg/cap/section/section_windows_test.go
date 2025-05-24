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

package section

import (
	kcapver "github.com/rabbitstack/fibratus/pkg/cap/version"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSection(t *testing.T) {
	s := New(Process, kcapver.ProcessSecV1, uint32(2456), uint32(30000))
	assert.Equal(t, Process, s.Type())
	assert.Equal(t, kcapver.ProcessSecV1, s.Version())
	assert.Equal(t, uint32(2456), s.Len())
	assert.Equal(t, uint32(30000), s.Size())
}

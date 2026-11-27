/*
 * Copyright 2026 by Nedim Sabic Sabic
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

package eval

import (
	"strings"
	"testing"

	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteFieldDocs(t *testing.T) {
	var b strings.Builder
	require.NoError(t, WriteFieldDocs(&b))
	docs := b.String()

	// every declared field is documented
	for _, fi := range fields.Get() {
		assert.Contains(t, docs, "### `"+string(fi.Field)+"`")
	}
	// what comes from the table and from the declaration
	assert.Contains(t, docs, "### `evt.pid`")
	assert.Contains(t, docs, "- Type: `")
	assert.Contains(t, docs, "- Argument: ")
}

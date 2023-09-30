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

package loldrivers

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDownload(t *testing.T) {
	assert.Nil(t, client)
	require.True(t, len(GetClient().Drivers()) > 0)
	assert.NotNil(t, client)
}

func TestMatchHash(t *testing.T) {
	ok, d := GetClient().MatchHash("_fixtures/d.sys")
	require.True(t, ok)
	assert.Equal(t, "d.sys", d.Filename)
}

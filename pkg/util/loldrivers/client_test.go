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
	"path/filepath"
	"testing"
)

func TestDownload(t *testing.T) {
	assert.Nil(t, c)
	InitClient()
	require.True(t, len(GetClient().Drivers()) > 0)
	assert.NotNil(t, c)

	var expectedSHA256 = "0440ef40c46fdd2b5d86e7feef8577a8591de862cfd7928cdbcc8f47b8fa3ffc"
	var foundSHA256 string

	for _, driver := range GetClient().Drivers() {
		if driver.Filename == "prokiller64.sys" {
			foundSHA256 = driver.SHA256
			break
		}
	}

	assert.Equal(t, expectedSHA256, foundSHA256)
}

func TestMatchHash(t *testing.T) {
	abs, err := filepath.Abs("_fixtures/d.sys")
	require.NoError(t, err)
	ok, d := GetClient().MatchHash(abs)
	require.True(t, ok)
	assert.Equal(t, "d.sys", d.Filename)
}

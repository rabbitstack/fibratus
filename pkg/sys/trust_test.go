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

package sys

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestIsCatalogSigned(t *testing.T) {
	executable, err := os.Executable()
	require.NoError(t, err)

	var tests = []struct {
		filename       string
		want           bool
		hasCertificate bool
		issuer         string
		subject        string
	}{
		{
			executable,
			false,
			false,
			"",
			"",
		},
		{
			filepath.Join(os.Getenv("windir"), "notepad.exe"),
			true,
			true,
			"US, Washington, Redmond, Microsoft Windows Production PCA 2011",
			"US, Washington, Redmond, Microsoft Corporation, Microsoft Windows",
		},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			c := NewCatalog()
			err := c.Open(tt.filename)
			defer c.Close()
			assert.Equal(t, tt.want, err == nil && c.IsCatalogSigned())
			cert, err := c.ParseCertificate()
			assert.True(t, tt.hasCertificate == (cert != nil))
			if cert != nil {
				require.NoError(t, err)
				assert.Equal(t, tt.subject, cert.Subject)
				assert.Equal(t, tt.issuer, cert.Issuer)
			}
		})
	}
}

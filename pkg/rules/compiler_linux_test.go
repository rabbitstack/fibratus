//go:build linux

/*
 * Copyright 2026 by Mostafa Moradian
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

package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/stretchr/testify/require"
)

func TestCompilerLinuxRule(t *testing.T) {
	rule := filepath.Join(t.TempDir(), "execve.yml")
	require.NoError(t, os.WriteFile(rule, []byte(`name: Linux process execution
id: 4d17dc44-cc9f-4f13-9a31-23c6529ff46e
version: 1.0.0
min-engine-version: 3.0.0
condition: evt.name = 'execve' and ps.name = 'bash'
`), 0o600))

	cfg := &config.Config{
		Filters: &config.Filters{
			Rules: config.Rules{FromPaths: []string{rule}},
		},
	}
	filters, result, err := newCompiler(ps.NewSnapshotter(), cfg).compile()
	require.NoError(t, err)
	require.Len(t, filters, 1)
	require.NotNil(t, result)
	require.True(t, result.HasProcEvents)
}

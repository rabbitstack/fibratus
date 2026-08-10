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

package config

import (
	"testing"

	"github.com/rabbitstack/fibratus/pkg/outputs/null"
	"github.com/stretchr/testify/require"
)

func TestEventlogOutputDefaultsToNull(t *testing.T) {
	c := NewWithOpts(WithRun())
	require.NoError(t, c.flags.Parse([]string{"--config-file=_fixtures/eventlog-output.yml"}))
	require.NoError(t, c.viper.BindPFlags(c.flags))
	require.NoError(t, c.TryLoadFile(c.GetConfigFile()))
	require.NoError(t, c.Init())

	require.IsType(t, &null.Config{}, c.Output.Output)
}

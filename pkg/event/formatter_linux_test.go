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

package event

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinuxFormatter(t *testing.T) {
	formatter, err := NewFormatter("{{.Type}} pid={{.Pid}} tid={{.Tid}}")
	require.NoError(t, err)

	event := &Event{
		Timestamp: time.Now(),
		PID:       42,
		Tid:       43,
		Type:      Execve,
		Name:      Execve.String(),
		Category:  Process,
	}
	assert.Equal(t, "execve pid=42 tid=43", string(formatter.Format(event)))
}

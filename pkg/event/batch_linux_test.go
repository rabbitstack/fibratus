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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLinuxBatchMarshalJSON(t *testing.T) {
	batch := NewBatch(&Event{PID: 42, Type: Execve}, &Event{PID: 43, Type: Exit})
	require.EqualValues(t, 2, batch.Len())

	var events []map[string]interface{}
	require.NoError(t, json.Unmarshal(batch.MarshalJSON(), &events))
	require.Len(t, events, 2)
}

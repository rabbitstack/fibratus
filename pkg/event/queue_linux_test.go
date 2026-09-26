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

	"github.com/stretchr/testify/require"
)

func TestLinuxQueuePush(t *testing.T) {
	queue := NewQueue(1, false, false)
	t.Cleanup(queue.Close)

	event := &Event{Type: Execve, PID: 42, Tid: 43}
	require.NoError(t, queue.Push(event))
	require.Same(t, event, <-queue.Events())
}

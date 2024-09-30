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

package kevent

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSequencer(t *testing.T) {
	sequencer := NewSequencer()
	require.NoError(t, sequencer.Reset())
	sequencer.seq = 0
	defer sequencer.Close()

	for i := 0; i < 10; i++ {
		sequencer.Increment()
	}
	assert.Equal(t, uint64(10), sequencer.Get())
	require.NoError(t, sequencer.Store())

	sequencer = NewSequencer()
	defer sequencer.Close()
	assert.Equal(t, uint64(10), sequencer.Get())

	require.NoError(t, sequencer.Reset())
	assert.Equal(t, uint64(0), sequencer.Get())
}

func TestSequencerMonotonic(t *testing.T) {
	sequencer := NewSequencer()
	require.NoError(t, sequencer.Reset())
	sequencer.seq = 0
	defer sequencer.Close()

	for i := 0; i < 10; i++ {
		sequencer.Increment()
	}
	require.NoError(t, sequencer.Store())

	sequencer = NewSequencer()
	defer sequencer.Close()
	sequencer.seq = uint64(0)

	require.Error(t, sequencer.Store())
	require.NoError(t, sequencer.Reset())
}

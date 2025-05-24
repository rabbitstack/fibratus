/*
 * Copyright 2021-present by Nedim Sabic Sabic
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
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestStackwalkDecorator(t *testing.T) {
	q := NewQueue(50, false, true)
	cd := NewStackwalkDecorator(q)

	e := &Event{
		Type:      CreateFile,
		Tid:       2484,
		PID:       859,
		CPU:       1,
		Seq:       2,
		Name:      "CreateFile",
		Timestamp: time.Now(),
		Category:  File,
		Params: Params{
			params.FileObject:    {Name: params.FileObject, Type: params.Uint64, Value: uint64(12456738026482168384)},
			params.FilePath:      {Name: params.FilePath, Type: params.UnicodeString, Value: "C:\\Windows\\system32\\user32.dll"},
			params.FileType:      {Name: params.FileType, Type: params.AnsiString, Value: "file"},
			params.FileOperation: {Name: params.FileOperation, Type: params.Enum, Value: uint32(1), Enum: fs.FileCreateDispositions},
		},
	}

	e1 := &Event{
		Type:      CreateFile,
		Tid:       2484,
		PID:       859,
		CPU:       1,
		Seq:       3,
		Name:      "CreateFile",
		Timestamp: time.Now(),
		Category:  File,
		Params: Params{
			params.FileObject:    {Name: params.FileObject, Type: params.Uint64, Value: uint64(12456738026482168384)},
			params.FilePath:      {Name: params.FilePath, Type: params.UnicodeString, Value: "C:\\Windows\\system32\\kernel32.dll"},
			params.FileType:      {Name: params.FileType, Type: params.AnsiString, Value: "file"},
			params.FileOperation: {Name: params.FileOperation, Type: params.Enum, Value: uint32(1), Enum: fs.FileCreateDispositions},
		},
	}

	cd.Push(e)
	cd.Push(e1)

	assert.Len(t, cd.buckets[e.StackID()], 2)

	sw := &Event{
		Type:      StackWalk,
		Tid:       2484,
		PID:       859,
		CPU:       1,
		Seq:       4,
		Name:      "StackWalk",
		Timestamp: time.Now(),
		Params: Params{
			params.Callstack: {Name: params.Callstack, Type: params.Slice, Value: []va.Address{0x7ffb5eb70dc4, 0x7ffb5c191deb, 0x7ffb3138592e}},
		},
	}

	evt := cd.Pop(sw)
	assert.Len(t, cd.buckets[e.StackID()], 1)
	assert.Equal(t, CreateFile, evt.Type)
	assert.True(t, evt.Params.Contains(params.Callstack))
	assert.Equal(t, "C:\\Windows\\system32\\user32.dll", evt.GetParamAsString(params.FilePath))
}

func init() {
	maxQueueTTLPeriod = time.Second * 2
	flusherInterval = time.Second
}

func TestStackwalkDecoratorFlush(t *testing.T) {
	q := NewQueue(50, false, true)
	q.RegisterListener(&DummyListener{})
	cd := NewStackwalkDecorator(q)
	defer cd.Stop()

	e := &Event{
		Type:      CreateFile,
		Tid:       2484,
		PID:       859,
		CPU:       1,
		Seq:       2,
		Name:      "CreateFile",
		Timestamp: time.Now(),
		Category:  File,
		Params: Params{
			params.FileObject:    {Name: params.FileObject, Type: params.Uint64, Value: uint64(12456738026482168384)},
			params.FilePath:      {Name: params.FilePath, Type: params.UnicodeString, Value: "C:\\Windows\\system32\\user32.dll"},
			params.FileType:      {Name: params.FileType, Type: params.AnsiString, Value: "file"},
			params.FileOperation: {Name: params.FileOperation, Type: params.Enum, Value: uint32(1), Enum: fs.FileCreateDispositions},
		},
	}

	cd.Push(e)
	assert.Len(t, cd.buckets[e.StackID()], 1)
	time.Sleep(time.Millisecond * 3100)

	evt := <-q.Events()
	assert.Len(t, cd.buckets[e.StackID()], 0)
	assert.Equal(t, CreateFile, evt.Type)
	assert.False(t, evt.Params.Contains(params.Callstack))
}

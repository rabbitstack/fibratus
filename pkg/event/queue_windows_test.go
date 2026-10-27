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

package event

import (
	"errors"
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// AddParamListener receives the event and appends a parameter to it
type AddParamListener struct {
	mock.Mock
}

func (l *AddParamListener) CanEnqueue() bool { return true }

func (l *AddParamListener) ProcessEvent(e *Event) (bool, error) {
	args := l.Called(e)
	e.Params.Append(params.FileAttributes, params.String, params.Str("HIDDEN"))
	return args.Bool(0), args.Error(1)
}

// DummyListener listeners just lets the event pass through
type DummyListener struct{}

func (l *DummyListener) CanEnqueue() bool { return true }

func (l *DummyListener) ProcessEvent(e *Event) (bool, error) {
	return true, nil
}

var ErrCantEnqueue = errors.New("cannot push event into the queue")

func TestQueuePush(t *testing.T) {
	var tests = []struct {
		name          string
		e             *Event
		err           error
		listeners     func() []Listener
		enqueueAlways bool
		isEnqueued    bool
	}{
		{
			"push event ok",
			&Event{
				Type:      CreateFile,
				Tid:       2484,
				PID:       859,
				CPU:       1,
				Seq:       2,
				Timestamp: time.Now(),
				Params: ParamsOf(
					NewParam(params.FileObject, params.Uint64, params.U64(uint64(12456738026482168384))),
					NewParam(params.FilePath, params.String, params.Str("C:\\Windows\\system32\\user32.dll")),
					NewParam(params.FileType, params.String, params.Str("file")),
					NewParam(params.FileOperation, params.Enum, params.U32(uint32(1)), params.WithEnum(fs.FileCreateDispositions)),
				),
			},
			nil,
			func() []Listener {
				l := &AddParamListener{}
				l.On("ProcessEvent", mock.Anything).Return(true, nil)
				return []Listener{l}
			},
			true,
			true,
		},
		{
			"push event listener error",
			&Event{
				Type:      CreateFile,
				Tid:       2484,
				PID:       859,
				CPU:       1,
				Seq:       2,
				Timestamp: time.Now(),
				Params: ParamsOf(
					NewParam(params.FileObject, params.Uint64, params.U64(uint64(12456738026482168384))),
					NewParam(params.FilePath, params.String, params.Str("C:\\Windows\\system32\\user32.dll")),
					NewParam(params.FileType, params.String, params.Str("file")),
					NewParam(params.FileOperation, params.Enum, params.U32(uint32(1)), params.WithEnum(fs.FileCreateDispositions)),
				),
			},
			ErrCantEnqueue,
			func() []Listener {
				l := &AddParamListener{}
				l.On("ProcessEvent", mock.Anything).Return(true, ErrCantEnqueue)
				return []Listener{l}
			},
			true,
			false,
		},
		{
			"push event one listener allows",
			&Event{
				Type:      CreateFile,
				Tid:       2484,
				PID:       859,
				CPU:       1,
				Seq:       2,
				Timestamp: time.Now(),
				Params: ParamsOf(
					NewParam(params.FileObject, params.Uint64, params.U64(uint64(12456738026482168384))),
					NewParam(params.FilePath, params.String, params.Str("C:\\Windows\\system32\\user32.dll")),
					NewParam(params.FileType, params.String, params.Str("file")),
					NewParam(params.FileOperation, params.Enum, params.U32(uint32(1)), params.WithEnum(fs.FileCreateDispositions)),
				),
			},
			nil,
			func() []Listener {
				l1, l2 := &AddParamListener{}, &AddParamListener{}
				l1.On("ProcessEvent", mock.Anything).Return(true, nil)
				l2.On("ProcessEvent", mock.Anything).Return(false, nil)
				return []Listener{l1, l2}
			},
			false,
			true,
		},
		{
			"push event listeners deny",
			&Event{
				Type:      CreateFile,
				Tid:       2484,
				PID:       859,
				CPU:       1,
				Seq:       2,
				Timestamp: time.Now(),
				Params: ParamsOf(
					NewParam(params.FileObject, params.Uint64, params.U64(uint64(12456738026482168384))),
					NewParam(params.FilePath, params.String, params.Str("C:\\Windows\\system32\\user32.dll")),
					NewParam(params.FileType, params.String, params.Str("file")),
					NewParam(params.FileOperation, params.Enum, params.U32(uint32(1)), params.WithEnum(fs.FileCreateDispositions)),
				),
			},
			nil,
			func() []Listener {
				l1, l2 := &AddParamListener{}, &AddParamListener{}
				l1.On("ProcessEvent", mock.Anything).Return(false, nil)
				l2.On("ProcessEvent", mock.Anything).Return(false, nil)
				return []Listener{l1, l2}
			},
			false,
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := NewQueue(100, false, tt.enqueueAlways)
			for _, lis := range tt.listeners() {
				q.RegisterListener(lis)
			}
			err := q.Push(tt.e)
			assert.Equal(t, err, tt.err)
			if tt.isEnqueued {
				assert.True(t, tt.e.Params.Contains(params.FileAttributes))
			}
			assert.True(t, len(q.Events()) > 0 == tt.isEnqueued)
		})
	}
}

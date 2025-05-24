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

package trim

import (
	"github.com/rabbitstack/fibratus/pkg/aggregator/transformers"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestTransform(t *testing.T) {
	evt := &event.Event{
		Type:        event.CreateFile,
		Tid:         2484,
		PID:         859,
		CPU:         1,
		Seq:         2,
		Name:        "CreateFile",
		Category:    event.File,
		Host:        "archrabbit",
		Description: "Creates or opens a new file, directory, I/O device, pipe, console",
		Params: event.Params{
			params.FileObject:    {Name: params.FileObject, Type: params.Uint64, Value: uint64(12456738026482168384)},
			params.FilePath:      {Name: params.FilePath, Type: params.UnicodeString, Value: "\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll"},
			params.FileType:      {Name: params.FileType, Type: params.AnsiString, Value: "file"},
			params.FileOperation: {Name: params.FileOperation, Type: params.AnsiString, Value: "overwriteif"},
			params.BasePrio:      {Name: params.BasePrio, Type: params.Int8, Value: int8(2)},
			params.PagePrio:      {Name: params.PagePrio, Type: params.Uint8, Value: uint8(2)},
			params.KstackLimit:   {Name: params.KstackLimit, Type: params.Address, Value: uint64(18884888488889)},
			params.StartTime:     {Name: params.StartTime, Type: params.Time, Value: time.Now()},
			params.ProcessID:     {Name: params.ProcessID, Type: params.PID, Value: uint32(1204)},
		},
		Metadata: map[event.MetadataKey]any{"foo": "bar", "fooz": "barz"},
	}

	transf, err := transformers.Load(transformers.Config{Type: transformers.Trim, Transformer: Config{Prefixes: []Trim{{Name: "file_path", Trim: "\\Device"}}, Suffixes: []Trim{{Name: "create_disposition", Trim: "if"}}}})
	require.NoError(t, err)

	require.NoError(t, transf.Transform(evt))
	filename, _ := evt.Params.GetString(params.FilePath)
	dispo, _ := evt.Params.GetString(params.FileOperation)

	assert.Equal(t, "\\HarddiskVolume2\\Windows\\system32\\user32.dll", filename)
	assert.Equal(t, "overwrite", dispo)
}

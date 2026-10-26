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
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/aggregator/transformers"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTransform(t *testing.T) {
	evt := &event.Event{
		Type: event.CreateFile,
		Tid:  2484,
		PID:  859,
		CPU:  1,
		Seq:  2,
		Host: "archrabbit",
		Params: event.ParamsOf(
			event.NewParam(params.FileObject, params.Uint64, params.U64(uint64(12456738026482168384))),
			event.NewParam(params.FilePath, params.String, params.Str("\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll")),
			event.NewParam(params.FileType, params.String, params.Str("file")),
			event.NewParam(params.FileOperation, params.String, params.Str("overwriteif")),
			event.NewParam(params.BasePrio, params.Int8, params.I8(int8(2))),
			event.NewParam(params.PagePrio, params.Uint8, params.U8(uint8(2))),
			event.NewParam(params.KstackLimit, params.Address, params.U64(uint64(18884888488889))),
			event.NewParam(params.StartTime, params.Time, params.Timestamp(time.Now())),
			event.NewParam(params.ProcessID, params.PID, params.U32(uint32(1204))),
		),
		Metadata: map[event.MetadataKey]any{"foo": "bar", "fooz": "barz"},
	}

	transf, err := transformers.Load(transformers.Config{Type: transformers.Trim, Transformer: Config{Prefixes: []Trim{{Name: "file_path", Trim: "\\Device"}}, Suffixes: []Trim{{Name: "create_disposition", Trim: "if"}}}})
	require.NoError(t, err)

	require.NoError(t, transf.Transform(evt))
	filename := evt.Params.GetStringByName(params.FilePath)
	dispo := evt.Params.GetStringByName(params.FileOperation)

	assert.Equal(t, "\\HarddiskVolume2\\Windows\\system32\\user32.dll", filename)
	assert.Equal(t, "overwrite", dispo)
}

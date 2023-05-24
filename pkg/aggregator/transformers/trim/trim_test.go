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
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestTransform(t *testing.T) {
	kevt := &kevent.Kevent{
		Type:        ktypes.CreateFile,
		Tid:         2484,
		PID:         859,
		CPU:         1,
		Seq:         2,
		Name:        "CreateFile",
		Category:    ktypes.File,
		Host:        "archrabbit",
		Description: "Creates or opens a new file, directory, I/O device, pipe, console",
		Kparams: kevent.Kparams{
			kparams.FileObject:    {Name: kparams.FileObject, Type: kparams.Uint64, Value: uint64(12456738026482168384)},
			kparams.FileName:      {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll"},
			kparams.FileType:      {Name: kparams.FileType, Type: kparams.AnsiString, Value: "file"},
			kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.AnsiString, Value: "overwriteif"},
			kparams.BasePrio:      {Name: kparams.BasePrio, Type: kparams.Int8, Value: int8(2)},
			kparams.PagePrio:      {Name: kparams.PagePrio, Type: kparams.Uint8, Value: uint8(2)},
			kparams.KstackLimit:   {Name: kparams.KstackLimit, Type: kparams.HexInt8, Value: kparams.Hex("ff")},
			kparams.StartTime:     {Name: kparams.StartTime, Type: kparams.Time, Value: time.Now()},
			kparams.ProcessID:     {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(1204)},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barz"},
	}

	transf, err := transformers.Load(transformers.Config{Type: transformers.Trim, Transformer: Config{Prefixes: []Trim{{Name: "file_name", Trim: "\\Device"}}, Suffixes: []Trim{{Name: "create_disposition", Trim: "if"}}}})
	require.NoError(t, err)

	require.NoError(t, transf.Transform(kevt))
	filename, _ := kevt.Kparams.GetString(kparams.FileName)
	dispo, _ := kevt.Kparams.GetString(kparams.FileOperation)

	assert.Equal(t, "\\HarddiskVolume2\\Windows\\system32\\user32.dll", filename)
	assert.Equal(t, "overwrite", dispo)
}

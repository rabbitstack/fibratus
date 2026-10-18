/*
 * Copyright 2019-2026 by Nedim Sabic Sabic
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

package probe

import (
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/util/key"
	"golang.org/x/sys/windows/registry"
)

// FileInfo stores file information obtained from event state.
type FileInfo struct {
	// Path represents the full file path in object manager format (e.g. \Device\HarddiskDevice1\)
	Path string

	// Type indicates the file type derived from the I/O operation.
	Type fs.FileType
}

func populateRegistryData(evt *event.Event) {
	path := evt.GetParamAsString(params.RegPath)

	// Get the type/value of the registry key and append to parameters
	rootkey, subkey := key.Format(path)
	if rootkey == key.Invalid {
		return
	}

	typ, val, err := rootkey.ReadValue(subkey)
	if err != nil {
		return
	}

	evt.AppendEnum(params.RegValueType, typ, key.RegistryValueTypes)

	switch typ {
	case registry.SZ, registry.EXPAND_SZ:
		evt.AppendParam(params.RegData, params.UnicodeString, val)
	case registry.MULTI_SZ:
		evt.AppendParam(params.RegData, params.Slice, val)
	case registry.BINARY:
		evt.AppendParam(params.RegData, params.Binary, val)
	case registry.QWORD:
		evt.AppendParam(params.RegData, params.Uint64, val)
	case registry.DWORD:
		evt.AppendParam(params.RegData, params.Uint32, uint32(val.(uint64)))
	}
}

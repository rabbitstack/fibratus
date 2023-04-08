//go:build kcap
// +build kcap

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

package kcap

import (
	"github.com/rabbitstack/fibratus/pkg/kcap/section"
	kcapver "github.com/rabbitstack/fibratus/pkg/kcap/version"
)

// magic has two purposes. It is used to identify kcap files. The magic is stored within the first 8 bytes of the file.
// The reader ensures the magic number matches this constant. Besides identifying the capture file, it serves as an
// input for initializing the byte order on the machine where kcap file is read. This implies capture can be taken on a
// machine with different endianness from the one capture is replayed.
const magic = 0x6669627261747573

// major represents the major digit of the kcap file format. Incrementing the major digit makes older kcap readers not
// capable to replay the capture file.
const major = uint8(1)

// minor represents the minor digit of the kcap file format
const minor = uint8(2)

// flags denotes extra flags for the purpose of the header description
const flags = uint64(0)

// ws writes the section block with the specified parameters.
func (w *writer) ws(typ section.Type, ver kcapver.Version, l, size uint32) error {
	sec := section.New(typ, ver, l, size)
	if _, err := w.zw.Write(sec[:]); err != nil {
		return errWriteSection(typ, err)
	}
	return nil
}

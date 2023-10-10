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

package ntfs

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"os"
	"strings"
	libntfs "www.velocidex.com/golang/go-ntfs/parser"
)

// FS provides raw access to Master File Table (MFT)
// and file data blobs mounted on the NTFS.
type FS struct {
	dev *os.File
}

// NewFS creates a new instance of the NTFS file system.
func NewFS() *FS {
	return &FS{}
}

// Read reads the file from the raw device at the specified offset and size.
func (fs *FS) Read(path string, offset, size int64) ([]byte, int, error) {
	defer func() {
		if err := recover(); err != nil {
			log.Warnf("unable to read %s from raw device: %v", path, err)
		}
	}()
	ntfs, err := fs.getNTFSContext(path)
	if err != nil {
		return nil, 0, err
	}
	defer ntfs.Close()

	data := make([]byte, size)

	// skip drive letter, semicolon and slash (e.g. C:\)
	filename := strings.ReplaceAll(path[3:], "\\", "/")
	reader, err := libntfs.GetDataForPath(ntfs, filename)
	if err != nil {
		return nil, 0, err
	}
	n, err := reader.ReadAt(data, offset)
	return data, n, err
}

// Close disposes all underlying resources.
func (fs *FS) Close() error {
	if fs.dev != nil {
		return fs.dev.Close()
	}
	return nil
}

func (fs *FS) getNTFSContext(path string) (*libntfs.NTFSContext, error) {
	if len(path) < 3 || path[1] != ':' {
		return nil, nil
	}

	// open raw device
	dev := fmt.Sprintf("\\\\.\\%s", path[:2])
	var err error
	fs.dev, err = os.Open(dev)
	if err != nil {
		return nil, err
	}

	const pageSize = 0x1000
	const cacheSize = 1000

	// create reader and NTFS context
	r, err := libntfs.NewPagedReader(fs.dev, pageSize, cacheSize)
	if err != nil {
		return nil, err
	}
	return libntfs.GetNTFSContext(r, 0)
}

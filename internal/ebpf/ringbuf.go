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

package ebpf

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

type ringReader struct {
	rd *ringbuf.Reader
}

func newRingReader(m *ebpf.Map) (*ringReader, error) {
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		return nil, fmt.Errorf("opening ring buffer: %w", err)
	}
	return &ringReader{rd: rd}, nil
}

func (r *ringReader) Read() ([]byte, error) {
	record, err := r.rd.Read()
	if err != nil {
		return nil, err
	}
	return record.RawSample, nil
}

func (r *ringReader) Close() error {
	if r == nil || r.rd == nil {
		return nil
	}
	return r.rd.Close()
}

func isRingClosed(err error) bool {
	return errors.Is(err, ringbuf.ErrClosed)
}

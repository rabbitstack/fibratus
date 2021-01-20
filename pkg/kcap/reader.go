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
	"context"
	"errors"
	"expvar"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/handle"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/kcap/section"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/util/bytes"
	log "github.com/sirupsen/logrus"
	zstd "github.com/valyala/gozstd"
	"io"
	"os"
	"path/filepath"
	"sync"
)

var (
	errKcapMagicMismatch = errors.New("invalid kcap file magic number")
	errMajorVer          = errors.New("incompatible kcap version format. Please upgrade Fibratus to newer version")
	errReadVersion       = func(s string, err error) error { return fmt.Errorf("couldn't read %s version digit: %v", s, err) }
	errReadSection       = func(s section.Type, err error) error { return fmt.Errorf("couldn't read %s section: %v", s, err) }

	kcapReadKevents           = expvar.NewInt("kcap.read.kevents")
	kcapReadBytes             = expvar.NewInt("kcap.read.bytes")
	kcapKeventUnmarshalErrors = expvar.NewInt("kcap.kevent.unmarshal.errors")
	kcapHandleUnmarshalErrors = expvar.NewInt("kcap.reader.handle.unmarshal.errors")
	kcapDroppedByFilter       = expvar.NewInt("kcap.reader.dropped.by.filter")
)

type reader struct {
	zr           *zstd.Reader
	f            *os.File
	psnapshotter ps.Snapshotter
	hsnapshotter handle.Snapshotter
	filter       filter.Filter
	config       *config.Config
	mu           sync.Mutex // guards the underlying zstd byte buffer
}

// NewReader builds a new instance of the kcap reader.
func NewReader(filename string, config *config.Config) (Reader, error) {
	if filepath.Ext(filename) == "" {
		filename += ".kcap"
	}
	f, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%q capture file does not exist", filename)
		}
		return nil, err
	}
	zr := zstd.NewReader(f)

	mag := make([]byte, 8)
	if n, err := zr.Read(mag); err != nil || n != 8 {
		return nil, errKcapMagicMismatch
	}
	bytes.InitNativeEndian(mag)
	// from now on all byte reads will use the endianness of the magic number.
	// This guarantees we'll be able to replay kcaptures that were taken
	// on a machine with a different endianness from the machine where
	// actual kcapture is being read.
	if bytes.ReadUint64(mag) != magic {
		return nil, errKcapMagicMismatch
	}

	maj := make([]byte, 1)
	min := make([]byte, 1)

	if n, err := zr.Read(maj); err != nil || n != 1 {
		return nil, errReadVersion("major", err)
	}
	if n, err := zr.Read(min); err != nil || n != 1 {
		return nil, errReadVersion("minor", err)
	}
	if maj[0] < major {
		return nil, errMajorVer
	}

	// read the flags bit vector but do nothing with it at the moment
	flags := make([]byte, 8)
	if n, err := zr.Read(flags); err != nil || n != 8 {
		return nil, fmt.Errorf("fail to read kcap flags: %v", err)
	}

	return &reader{f: f, zr: zr, config: config}, nil
}

func (r *reader) SetFilter(f filter.Filter) { r.filter = f }

func (r *reader) Read(ctx context.Context) (chan *kevent.Kevent, chan error) {
	errsc := make(chan error, 100)
	keventsc := make(chan *kevent.Kevent, 2000)
	go func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			var sec section.Section
			if _, err := io.ReadFull(r.zr, sec[:]); err != nil {
				if err != io.EOF {
					errsc <- err
					continue
				}
				break
			}

			l := sec.Size()
			buf := make([]byte, l)
			if _, err := io.ReadFull(r.zr, buf); err != nil {
				if err != io.EOF {
					errsc <- err
					continue
				}
				break
			}
			kevt, err := kevent.NewFromKcap(buf)
			if err != nil {
				errsc <- fmt.Errorf("fail to unmarshal kevent: %v", err)
				kcapKeventUnmarshalErrors.Add(1)
				continue
			}
			kcapReadBytes.Add(int64(len(buf)))
			// update the state of the ps/handle snapshotters
			if err := r.updateSnapshotters(kevt); err != nil {
				log.Warn(err)
			}
			// push the event to the chanel
			r.read(kevt, keventsc)
		}
	}()

	return keventsc, errsc
}

func (r *reader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.zr != nil {
		r.zr.Release()
	}
	if r.f != nil {
		return r.f.Close()
	}
	return nil
}

func (r *reader) read(kevt *kevent.Kevent, keventsc chan *kevent.Kevent) {
	if kevt.Type.Dropped(false) {
		return
	}
	if r.filter != nil && !r.filter.Run(kevt) {
		kcapDroppedByFilter.Add(1)
		return
	}
	keventsc <- kevt
	kcapReadKevents.Add(1)
}

func (r *reader) updateSnapshotters(kevt *kevent.Kevent) error {
	switch kevt.Type {
	case ktypes.TerminateThread, ktypes.TerminateProcess, ktypes.UnloadImage:
		if err := r.psnapshotter.Remove(kevt); err != nil {
			return err
		}
	case ktypes.CreateProcess,
		ktypes.CreateThread,
		ktypes.LoadImage,
		ktypes.EnumImage,
		ktypes.EnumProcess, ktypes.EnumThread:
		if err := r.psnapshotter.WriteFromKcap(kevt); err != nil {
			return err
		}
	case ktypes.CreateHandle:
		if err := r.hsnapshotter.Write(kevt); err != nil {
			return err
		}
	case ktypes.CloseHandle:
		if err := r.hsnapshotter.Remove(kevt); err != nil {
			return err
		}
	}
	if kevt.PS == nil {
		kevt.PS = r.psnapshotter.Find(kevt.PID)
	}
	return nil
}

func (r *reader) RecoverSnapshotters() (handle.Snapshotter, ps.Snapshotter, error) {
	hsnap, err := r.recoverHandleSnapshotter()
	if err != nil {
		return nil, nil, err
	}
	r.psnapshotter = ps.NewSnapshotterFromKcap(hsnap, r.config)
	return hsnap, r.psnapshotter, nil
}

func (r *reader) recoverHandleSnapshotter() (handle.Snapshotter, error) {
	var sec section.Section
	if _, err := io.ReadFull(r.zr, sec[:]); err != nil {
		return nil, errReadSection(section.Handle, err)
	}
	nbHandles := sec.Len()
	handles := make([]htypes.Handle, nbHandles)
	for i := 0; i < int(nbHandles); i++ {
		b := make([]byte, 2)
		if _, err := io.ReadFull(r.zr, b); err != nil {
			continue
		}

		l := bytes.ReadUint16(b)
		b = make([]byte, l)
		if _, err := io.ReadFull(r.zr, b); err != nil {
			continue
		}

		var err error
		handles[i], err = htypes.NewFromKcap(b)
		if err != nil {
			kcapHandleUnmarshalErrors.Add(1)
		}
	}
	r.hsnapshotter = handle.NewFromKcap(handles)
	return r.hsnapshotter, nil
}

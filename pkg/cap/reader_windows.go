//go:build cap
// +build cap

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

package cap

import (
	"context"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/cap/section"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/handle"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/util/bytes"
	log "github.com/sirupsen/logrus"
	zstd "github.com/valyala/gozstd"
	"io"
	"os"
	"path/filepath"
	"sync"
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

// NewReader builds a new instance of the cap reader.
func NewReader(filename string, config *config.Config) (Reader, error) {
	if filepath.Ext(filename) == "" {
		filename += ".cap"
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
		return nil, ErrCapMagicMismatch
	}
	bytes.InitNativeEndian(mag)
	// from now on all byte reads will use the endianness of the magic number.
	// This guarantees we'll be able to replay captures that were taken
	// on a machine with a different endianness from the machine where
	// actual capture is being read.
	if bytes.ReadUint64(mag) != magic {
		return nil, ErrCapMagicMismatch
	}

	maj := make([]byte, 1)
	min := make([]byte, 1)

	if n, err := zr.Read(maj); err != nil || n != 1 {
		return nil, ErrReadVersion("major", err)
	}
	if n, err := zr.Read(min); err != nil || n != 1 {
		return nil, ErrReadVersion("minor", err)
	}
	if maj[0] < major {
		return nil, ErrMajorVer(maj[0], min[0])
	}

	// read the flags bit vector but do nothing with it at the moment
	flags := make([]byte, 8)
	if n, err := zr.Read(flags); err != nil || n != 8 {
		return nil, fmt.Errorf("fail to read cap flags: %v", err)
	}

	return &reader{f: f, zr: zr, config: config}, nil
}

func (r *reader) SetFilter(f filter.Filter) { r.filter = f }

func (r *reader) Read(ctx context.Context) (chan *event.Event, chan error) {
	errsc := make(chan error, 100)
	eventsc := make(chan *event.Event, 2000)
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
			evt, err := event.NewFromCapture(buf, sec.Version())
			if err != nil {
				errsc <- fmt.Errorf("fail to unmarshal event: %v", err)
				capKeventUnmarshalErrors.Add(1)
				continue
			}
			capReadBytes.Add(int64(len(buf)))
			// update the state of the ps/handle snapshotters
			if err := r.updateSnapshotters(evt); err != nil {
				log.Warn(err)
			}
			// push the event to the chanel
			r.read(evt, eventsc)
		}
	}()

	return eventsc, errsc
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

func (r *reader) read(evt *event.Event, eventsc chan *event.Event) {
	if evt.Type.OnlyState() {
		return
	}
	if r.filter != nil && !r.filter.Run(evt) {
		capDroppedByFilter.Add(1)
		return
	}
	eventsc <- evt
	capReadKevents.Add(1)
}

func (r *reader) updateSnapshotters(evt *event.Event) error {
	switch evt.Type {
	case event.TerminateProcess:
		if err := r.psnapshotter.Remove(evt); err != nil {
			return err
		}
	case event.TerminateThread:
		pid := evt.Params.MustGetPid()
		tid := evt.Params.MustGetTid()
		if err := r.psnapshotter.RemoveThread(pid, tid); err != nil {
			return err
		}
	case event.UnloadImage:
		pid := evt.Params.MustGetPid()
		addr := evt.Params.TryGetAddress(params.ImageBase)
		if err := r.psnapshotter.RemoveModule(pid, addr); err != nil {
			return err
		}
	case event.CreateProcess,
		event.ProcessRundown,
		event.LoadImage,
		event.ImageRundown,
		event.CreateThread,
		event.ThreadRundown:
		if err := r.psnapshotter.WriteFromCapture(evt); err != nil {
			return err
		}
	case event.CreateHandle:
		if err := r.hsnapshotter.Write(evt); err != nil {
			return err
		}
	case event.CloseHandle:
		if err := r.hsnapshotter.Remove(evt); err != nil {
			return err
		}
	}
	if evt.PS == nil {
		_, evt.PS = r.psnapshotter.Find(evt.PID)
	}
	return nil
}

func (r *reader) RecoverSnapshotters() (handle.Snapshotter, ps.Snapshotter, error) {
	hsnap, err := r.recoverHandleSnapshotter()
	if err != nil {
		return nil, nil, err
	}
	r.psnapshotter = ps.NewSnapshotterFromCapture(hsnap, r.config)
	return hsnap, r.psnapshotter, nil
}

func (r *reader) recoverHandleSnapshotter() (handle.Snapshotter, error) {
	var sec section.Section
	if _, err := io.ReadFull(r.zr, sec[:]); err != nil {
		return nil, ErrReadSection(section.Handle, err)
	}
	nhandles := sec.Len()
	handles := make([]htypes.Handle, nhandles)
	for i := 0; i < int(nhandles); i++ {
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
			capHandleUnmarshalErrors.Add(1)
		}
	}
	r.hsnapshotter = handle.NewFromKcap(handles)
	return r.hsnapshotter, nil
}

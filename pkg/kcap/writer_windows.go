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
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/kcap/section"
	kcapver "github.com/rabbitstack/fibratus/pkg/kcap/version"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/util/bytes"
	zstd "github.com/valyala/gozstd"
)

type stats struct {
	kcapFile       string
	kevtsWritten   uint64
	bytesWritten   uint64
	handlesWritten uint64
	procsWritten   uint64
}

func (s *stats) incKevts(kevt *kevent.Kevent) {
	if !kevt.Type.OnlyState() {
		atomic.AddUint64(&s.kevtsWritten, 1)
	}
}
func (s *stats) incBytes(bytes uint64) { atomic.AddUint64(&s.bytesWritten, bytes) }
func (s *stats) incHandles()           { atomic.AddUint64(&s.handlesWritten, 1) }
func (s *stats) incProcs(kevt *kevent.Kevent) {
	if kevt.IsCreateProcess() || kevt.IsProcessRundown() {
		atomic.AddUint64(&s.procsWritten, 1)
	}
}

func (s *stats) printStats() {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetTitle("Capture Statistics")
	t.SetStyle(table.StyleLight)

	t.AppendRow(table.Row{"File", filepath.Base(s.kcapFile)})
	t.AppendSeparator()

	t.AppendRow(table.Row{"Events written", atomic.LoadUint64(&s.kevtsWritten)})
	t.AppendRow(table.Row{"Bytes written", atomic.LoadUint64(&s.bytesWritten)})
	t.AppendRow(table.Row{"Processes written", atomic.LoadUint64(&s.procsWritten)})
	t.AppendRow(table.Row{"Handles written", atomic.LoadUint64(&s.handlesWritten)})

	f, err := os.Stat(s.kcapFile)
	if err != nil {
		t.Render()
		return
	}
	t.AppendSeparator()
	t.AppendRow(table.Row{"Capture size", humanize.Bytes(uint64(f.Size()))})

	t.Render()
}

type writer struct {
	zw      *zstd.Writer
	f       *os.File
	flusher *time.Ticker
	psnap   ps.Snapshotter
	hsnap   handle.Snapshotter
	stop    chan struct{}
	// stats contains the capture statistics
	stats *stats
	// mu protects the underlying zstd buffer
	mu sync.Mutex
	// released indicates if the zstd buffer is disposed
	released atomic.Bool
}

// NewWriter constructs a new instance of the kcap writer.
func NewWriter(filename string, psnap ps.Snapshotter, hsnap handle.Snapshotter) (Writer, error) {
	if filepath.Ext(filename) == "" {
		filename += ".kcap"
	}
	f, err := os.Create(filename)
	if err != nil {
		return nil, err
	}
	zw := zstd.NewWriter(f)
	// start by writing the kcap header that is composed
	// of magic number, major/minor digits and the optional
	// flags bit vector. The flags bit vector is reserved
	// for the future uses.
	// The header is followed by the handle snapshot.
	// It contains the current state of the system handles
	// at the time the capture was started.
	// Handle snapshots are prepended with a section
	// that describes the version and the number of handles
	// in the snapshot. This information is used by the reader to
	// restore the state of the snapshotters.
	if _, err := zw.Write(bytes.WriteUint64(magic)); err != nil {
		return nil, ErrWriteMagic(err)
	}
	if _, err := zw.Write([]byte{major}); err != nil {
		return nil, ErrWriteVersion("major", err)
	}
	if _, err := zw.Write([]byte{minor}); err != nil {
		return nil, ErrWriteVersion("minor", err)
	}
	if _, err := zw.Write(bytes.WriteUint64(flags)); err != nil {
		return nil, err
	}

	w := &writer{
		zw:      zw,
		f:       f,
		flusher: time.NewTicker(time.Second),
		psnap:   psnap,
		hsnap:   hsnap,
		stop:    make(chan struct{}),
		stats:   &stats{kcapFile: filename},
	}

	if err := w.writeSnapshots(); err != nil {
		return nil, err
	}

	go w.flush()

	return w, nil
}

func (w *writer) writeSnapshots() error {
	handles := w.hsnap.GetSnapshot()
	// write handle section and the data blocks
	err := w.ws(section.Handle, kcapver.HandleSecV1, uint32(len(handles)), 0)
	if err != nil {
		return err
	}

	writeHandle := func(buf []byte) error {
		l := bytes.WriteUint16(uint16(len(buf)))
		if _, err := w.zw.Write(l); err != nil {
			return err
		}
		if _, err := w.zw.Write(buf); err != nil {
			return err
		}
		return nil
	}

	for _, khandle := range handles {
		if err := writeHandle(khandle.Marshal()); err != nil {
			handleWriteErrors.Add(1)
			continue
		}
		w.stats.incHandles()
	}
	return w.zw.Flush()
}

func (w *writer) Write(kevtsc <-chan *kevent.Kevent, errs <-chan error) chan error {
	errsc := make(chan error, 100)
	go func() {
		for {
			select {
			case kevt := <-kevtsc:
				b := kevt.MarshalRaw()
				l := len(b)
				if l == 0 {
					continue
				}
				// write event buffer
				err := w.write(b)
				if err != nil {
					errsc <- err
					continue
				}
				// update stats
				w.stats.incKevts(kevt)
				w.stats.incBytes(uint64(l))
				w.stats.incProcs(kevt)
			case err := <-errs:
				errsc <- err
				kstreamConsumerErrors.Add(1)
			case <-w.stop:
				return
			}
		}
	}()
	return errsc
}

func (w *writer) write(b []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	l := len(b)
	if l > maxKevtSize {
		overflowKevents.Add(1)
		return fmt.Errorf("event size overflow by %d bytes", l-maxKevtSize)
	}
	if err := w.ws(section.Kevt, kcapver.KevtSecV2, 0, uint32(l)); err != nil {
		kevtWriteErrors.Add(1)
		return err
	}
	if _, err := w.zw.Write(b); err != nil {
		kevtWriteErrors.Add(1)
		return err
	}
	return nil
}

func (w *writer) Close() error {
	w.stats.printStats()

	close(w.stop)

	w.flusher.Stop()
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.zw != nil {
		if err := w.zw.Close(); err != nil {
			return err
		}
		w.zw.Release()
		w.released.Store(true)
	}
	if w.f != nil {
		return w.f.Close()
	}
	return nil
}

func (w *writer) flush() {
	for {
		select {
		case <-w.flusher.C:
			if w.released.Load() {
				return
			}
			w.mu.Lock()
			err := w.zw.Flush()
			w.mu.Unlock()
			if err != nil {
				flusherErrors.Add(err.Error(), 1)
			}
		case <-w.stop:
			return
		}
	}
}

//go:build windows

/*
 * Copyright 2021-present by Nedim Sabic Sabic
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

package policy

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

const notifyFilter = windows.FILE_NOTIFY_CHANGE_FILE_NAME |
	windows.FILE_NOTIFY_CHANGE_DIR_NAME |
	windows.FILE_NOTIFY_CHANGE_SIZE |
	windows.FILE_NOTIFY_CHANGE_LAST_WRITE |
	windows.FILE_NOTIFY_CHANGE_CREATION

// fileNotifyInformation mirrors the FILE_NOTIFY_INFORMATION structure.
type fileNotifyInformation struct {
	NextEntryOffset uint32
	Action          uint32
	FileNameLength  uint32
	FileName        uint16
}

// dirWatcher watches directories for changes via ReadDirectoryChangesW.
// Each directory is served by a goroutine that blocks in a synchronous
// read until something changes or the watcher is closed.
type dirWatcher struct {
	handles []windows.Handle
	wg      sync.WaitGroup
	closing atomic.Bool
	notify  func()
}

func newDirWatcher(dirs []string, notify func()) (watcher, error) {
	w := &dirWatcher{notify: notify}
	for _, dir := range dirs {
		p, err := windows.UTF16PtrFromString(dir)
		if err != nil {
			w.release()
			return nil, err
		}
		h, err := windows.CreateFile(
			p,
			windows.FILE_LIST_DIRECTORY,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			nil,
			windows.OPEN_EXISTING,
			windows.FILE_FLAG_BACKUP_SEMANTICS,
			0,
		)
		if err != nil {
			w.release()
			return nil, fmt.Errorf("unable to open directory %s: %v", dir, err)
		}
		w.handles = append(w.handles, h)
		w.wg.Add(1)
		go w.read(dir, h)
	}
	return w, nil
}

func (w *dirWatcher) read(dir string, h windows.Handle) {
	defer w.wg.Done()
	buf := make([]byte, 64*1024)
	for !w.closing.Load() {
		var n uint32
		err := windows.ReadDirectoryChanges(h, &buf[0], uint32(len(buf)), false, notifyFilter, &n, nil, 0)
		if err != nil {
			if w.closing.Load() || err == windows.ERROR_OPERATION_ABORTED {
				return
			}
			log.Errorf("directory change notification for %s failed: %v", dir, err)
			return
		}
		// a zero-length result means the notification buffer overflowed,
		// so we can't tell what changed and have to assume the worst
		if n == 0 || hasRelevantChange(buf[:n]) {
			w.notify()
		}
	}
}

// hasRelevantChange determines if any of the notifications refer to a YAML file.
func hasRelevantChange(buf []byte) bool {
	var off uint32
	for {
		if int(off)+int(unsafe.Offsetof(fileNotifyInformation{}.FileName)) > len(buf) {
			return true
		}
		info := (*fileNotifyInformation)(unsafe.Pointer(&buf[off]))
		n := info.FileNameLength / 2
		name := windows.UTF16ToString(unsafe.Slice(&info.FileName, n))
		if isValidExt(name) {
			return true
		}
		if info.NextEntryOffset == 0 {
			return false
		}
		off += info.NextEntryOffset
	}
}

func (w *dirWatcher) release() {
	w.closing.Store(true)
	for _, h := range w.handles {
		_ = windows.CancelIoEx(h, nil)
	}
	w.wg.Wait()
	for _, h := range w.handles {
		_ = windows.CloseHandle(h)
	}
	w.handles = nil
}

// Close cancels the pending reads and releases the directory handles.
func (w *dirWatcher) Close() error {
	w.closing.Store(true)
	done := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(done)
	}()
	// a read issued between the closing check and the cancel
	// would never be canceled, so keep cancelling until all
	// readers have exited
	for {
		for _, h := range w.handles {
			_ = windows.CancelIoEx(h, nil)
		}
		select {
		case <-done:
			for _, h := range w.handles {
				_ = windows.CloseHandle(h)
			}
			w.handles = nil
			return nil
		case <-time.After(10 * time.Millisecond):
		}
	}
}

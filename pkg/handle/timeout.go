//go:build windows
// +build windows

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

package handle

import (
	"errors"
	"expvar"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"golang.org/x/sys/windows"
	"unsafe"
)

var (
	ini                  windows.Handle
	done                 windows.Handle
	objectNameInCallback string

	waitTimeoutCounts = expvar.NewInt("handle.wait.timeouts")
)

func init() {
	ini, _ = windows.CreateEvent(nil, 0, 0, nil)
	done, _ = windows.CreateEvent(nil, 0, 0, nil)
}

// GetHandleWithTimeout is in charge of resolving handle names on handle instances that are under the risk
// of producing a deadlock, and thus hanging the caller thread. To prevent this kind of unwanted scenarios,
// deadlock aware timeout calls into `NtQueryObject` in a separate native thread. The thread is blocked waiting
// to be signaled by an event, but the query thread also signals back the main thread after completion of the
// `NtQueryObject` call.
// If the query thread doesn't notify the main thread after a prudent timeout, then the query thread is killed.
// Subsequent calls for handle name resolution will recreate the thread in case of it not being alive.
func GetHandleWithTimeout(handle windows.Handle, timeout uint32) (string, error) {
	if err := windows.ResetEvent(ini); err != nil {
		return "", fmt.Errorf("couldn't reset init event: %v", err)
	}
	if err := windows.ResetEvent(done); err != nil {
		return "", fmt.Errorf("couldn't reset done event: %v", err)
	}
	if err := windows.SetEvent(ini); err != nil {
		return "", err
	}
	thread := sys.CreateThread(
		nil,
		0,
		windows.NewCallback(getObjectNameCallback),
		uintptr(unsafe.Pointer(&handle)),
		0,
		nil)
	if thread == 0 {
		return "", fmt.Errorf("cannot create handle query thread: %v", windows.GetLastError())
	}
	defer sys.TerminateThread(thread, 0)

	s, err := windows.WaitForSingleObject(done, timeout)
	if s == windows.WAIT_OBJECT_0 {
		return objectNameInCallback, nil
	}
	if err == windows.WAIT_TIMEOUT {
		waitTimeoutCounts.Add(1)
		// kill the thread and wait for its termination to orderly cleanup resources
		if err := sys.TerminateThread(thread, 0); err != nil {
			return "", fmt.Errorf("unable to terminate timeout thread: %v", err)
		}
		if _, err := windows.WaitForSingleObject(thread, timeout); err != nil {
			return "", fmt.Errorf("failed awaiting timeout thread termination: %v", err)
		}
		_ = windows.CloseHandle(thread)
		return "", errors.New("couldn't resolve handle name due to timeout")
	}
	return "", nil
}

// CloseTimeout releases event and thread handles.
func CloseTimeout() error {
	_ = windows.CloseHandle(ini)
	_ = windows.CloseHandle(done)
	return nil
}

func getObjectNameCallback(ctx uintptr) uintptr {
	for {
		s, err := windows.WaitForSingleObject(ini, windows.INFINITE)
		if err != nil || s != windows.WAIT_OBJECT_0 {
			break
		}
		handle := *(*windows.Handle)(unsafe.Pointer(ctx))
		objectNameInCallback, err = QueryObjectName(handle)
		if err != nil {
			if err := windows.SetEvent(done); err != nil {
				break
			}
			continue
		}
		if err := windows.SetEvent(done); err != nil {
			break
		}
	}
	return 0
}

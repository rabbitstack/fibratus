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
)

type timeout struct {
	ini    windows.Handle
	done   windows.Handle
	thread windows.Handle
	in     chan windows.Handle
	out    chan string
}

var tmt timeout

var (
	waitTimeoutCounts = expvar.NewInt("handle.wait.timeouts")
)

func init() {
	tmt.ini, _ = windows.CreateEvent(nil, 0, 0, nil)
	tmt.done, _ = windows.CreateEvent(nil, 0, 0, nil)
	tmt.in = make(chan windows.Handle, 1)
	tmt.out = make(chan string, 1)
}

// GetHandleWithTimeout is in charge of resolving handle names on handle instances that are under the risk
// of producing a deadlock, and thus hanging the caller thread. To prevent this kind of unwanted scenarios,
// deadlock aware timeout calls into `NtQueryObject` in a separate native thread. The thread is blocked waiting
// to be signaled by an event, but the query thread also signals back the main thread after completion of the
// `NtQueryObject` call.
// If the query thread doesn't notify the main thread after a prudent timeout, then the query thread is killed.
// Subsequent calls for handle name resolution will recreate the thread in case of it not being alive.
func GetHandleWithTimeout(handle windows.Handle, timeout uint32) (string, error) {
	if tmt.thread == 0 {
		if err := windows.ResetEvent(tmt.ini); err != nil {
			return "", fmt.Errorf("couldn't reset init event: %v", err)
		}
		if err := windows.ResetEvent(tmt.done); err != nil {
			return "", fmt.Errorf("couldn't reset done event: %v", err)
		}
		tmt.in = make(chan windows.Handle, 1)
		tmt.out = make(chan string, 1)
		tmt.thread = sys.CreateThread(
			nil,
			0,
			windows.NewCallback(timeoutFn),
			0,
			0,
			nil)
		if tmt.thread == 0 {
			return "", fmt.Errorf("cannot create handle query thread: %v", windows.GetLastError())
		}
	}

	tmt.in <- handle
	if err := windows.SetEvent(tmt.ini); err != nil {
		return "", err
	}

	evt, err := windows.WaitForSingleObject(tmt.done, timeout)
	if err != nil || evt == windows.WAIT_FAILED {
		// consume pushed handle
		<-tmt.in
		return "", nil
	}
	if evt == windows.WAIT_OBJECT_0 {
		return <-tmt.out, nil
	}
	if windows.Errno(evt) == windows.WAIT_TIMEOUT {
		waitTimeoutCounts.Add(1)
		// kill the thread and wait for its termination to orderly cleanup resources
		if err := sys.TerminateThread(tmt.thread, 0); err != nil {
			return "", fmt.Errorf("unable tmt terminate timeout thread: %v", err)
		}
		if _, err := windows.WaitForSingleObject(tmt.thread, timeout); err != nil {
			tmt.thread = 0
			return "", fmt.Errorf("failed awaiting timeout thread termination: %v", err)
		}
		_ = windows.CloseHandle(tmt.thread)
		tmt.thread = 0
		return "", errors.New("couldn't resolve handle name due to timeout")
	}
	return "", nil
}

// CloseTimeout releases event and thread handles.
func CloseTimeout() error {
	_ = windows.CloseHandle(tmt.ini)
	_ = windows.CloseHandle(tmt.done)
	if tmt.thread != 0 {
		return sys.TerminateThread(tmt.thread, 0)
	}
	return nil
}

// timeoutFn waits for the initial event signalization and then
// pulls the handle identifier from the input channel. With handle
// identifier inside the callback function, the object is queried.
// If the query is successful, the result is pushed to the output
// channel, and the done event is signaled to indicate the object
// name can be retrieved.
func timeoutFn(ctx uintptr) uintptr {
	for {
		s, err := windows.WaitForSingleObject(tmt.ini, windows.INFINITE)
		if err != nil || s != windows.WAIT_OBJECT_0 {
			break
		}
		obj, err := QueryObjectName(<-tmt.in)
		tmt.out <- obj
		if err != nil {
			if err := windows.SetEvent(tmt.done); err != nil {
				break
			}
			continue
		}
		if err := windows.SetEvent(tmt.done); err != nil {
			break
		}
	}
	return 0
}

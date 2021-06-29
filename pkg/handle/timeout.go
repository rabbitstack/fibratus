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
	"github.com/rabbitstack/fibratus/pkg/syscall/handle"
	"github.com/rabbitstack/fibratus/pkg/syscall/object"
	"github.com/rabbitstack/fibratus/pkg/syscall/thread"
	"sync/atomic"
	"syscall"
)

var (
	threadHandle handle.Handle
	rawHandle    atomic.Value
	ini          object.Event
	done         object.Event
	name         string

	waitTimeoutCounts = expvar.NewInt("handle.wait.timeouts")
)

func init() {
	ini, _ = object.NewEvent(false, false)
	done, _ = object.NewEvent(false, false)
}

// GetHandleWithTimeout is in charge of resolving handle names on handle instances that are under the risk
// of producing a deadlock, and thus hanging the caller thread. To prevent this kind of unwanted scenarios,
// deadlock aware timeout calls into `NtQueryObject` in a separate native thread. The thread is reused across
// invocations as it is blocked waiting to be signaled by an event, but the query thread also signals back the main
// thread after completion of the `NtQueryObject` call. If the query thread doesn't notify the main thread after a prudent
// timeout, then the query thread is killed. Subsequent calls for handle name resolution will recreate the thread in case
// of it not being alive.
func GetHandleWithTimeout(handle handle.Handle, timeout uint32) (string, error) {
	if threadHandle == 0 {
		if err := ini.Reset(); err != nil {
			return "", fmt.Errorf("couldn't reset init event: %v", err)
		}
		if err := done.Reset(); err != nil {
			return "", fmt.Errorf("couldn't reset done event: %v", err)
		}
		h, _, err := thread.Create(nil, syscall.NewCallback(cb))
		if err != nil {
			return "", fmt.Errorf("cannot create handle query thread: %v", err)
		}
		threadHandle = h
	}

	rawHandle.Store(handle)

	if err := ini.Set(); err != nil {
		return "", err
	}

	switch s, _ := syscall.WaitForSingleObject(syscall.Handle(done), timeout); s {
	case syscall.WAIT_OBJECT_0:
		return name, nil
	case syscall.WAIT_TIMEOUT:
		waitTimeoutCounts.Add(1)
		// kill the thread and wait for its termination to orderly cleanup resources
		if err := thread.Terminate(threadHandle, 0); err != nil {
			return "", fmt.Errorf("unable to terminate timeout thread: %v", err)
		}
		if _, err := syscall.WaitForSingleObject(syscall.Handle(threadHandle), timeout); err != nil {
			return "", fmt.Errorf("failed awaiting timeout thread termination: %v", err)
		}
		threadHandle = 0
		threadHandle.Close()

		return "", errors.New("couldn't resolve handle name due to timeout")
	}
	return "", nil
}

// CloseTimeout releases handle timeut resources.
func CloseTimeout() error {
	if err := ini.Close(); err != nil {
		return done.Close()
	}
	threadHandle.Close()
	return done.Close()
}

func cb(ctx uintptr) uintptr {
	for {
		s, err := syscall.WaitForSingleObject(syscall.Handle(ini), syscall.INFINITE)
		if err != nil || s != syscall.WAIT_OBJECT_0 {
			break
		}
		name, err = queryObjectName(rawHandle.Load().(handle.Handle))
		if err != nil {
			if err := done.Set(); err != nil {
				break
			}
			continue
		}
		if err := done.Set(); err != nil {
			break
		}
	}
	return 0
}

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

package etw

import (
	"fmt"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// terminateProcess terminates the process, provided that the creation time of the
// live process matches the expected start time. The unknown start time is not verified.
// Terminating the process that doesn't exist is not considered an error.
func terminateProcess(pid uint32, started time.Time) error {
	proc, err := windows.OpenProcess(syscall.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		errno, ok := err.(windows.Errno)
		if ok && (errno.Is(os.ErrNotExist) || err == windows.ERROR_INVALID_PARAMETER) {
			return nil
		}
		return fmt.Errorf("couldn't open pid %d for termination: %v", pid, err)
	}
	defer func() {
		_ = windows.CloseHandle(proc)
	}()

	if !started.IsZero() {
		var creation, exit, kernel, user windows.Filetime
		if err := windows.GetProcessTimes(proc, &creation, &exit, &kernel, &user); err == nil {
			diff := time.Unix(0, creation.Nanoseconds()).Sub(started)
			if diff < 0 {
				diff = -diff
			}
			if diff > startTimeTolerance {
				return errPIDReused
			}
		}
	}

	if err := windows.TerminateProcess(proc, uint32(1)); err != nil {
		return fmt.Errorf("failed to kill pid %d: %v", pid, err)
	}
	return nil
}

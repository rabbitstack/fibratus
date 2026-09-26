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

package action

import (
	"fmt"
	"os"
	"syscall"

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

// Kill terminates all processes referenced by the action context.
func Kill(ctx *config.ActionContext) error {
	if ctx == nil {
		return nil
	}
	pids := ctx.UniquePids()
	log.Infof("killing pids=%v", pids)

	errs := make([]error, 0)
	for _, pid := range pids {
		err := terminate(pid)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return multierror.Wrap(errs...)
}

func terminate(pid uint32) error {
	proc, err := windows.OpenProcess(syscall.PROCESS_TERMINATE, false, pid)
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
	err = windows.TerminateProcess(proc, uint32(1))
	if err != nil {
		return fmt.Errorf("failed to kill pid %d: %v", pid, err)
	}
	return nil
}

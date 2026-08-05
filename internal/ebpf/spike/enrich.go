//go:build linux

/*
 * Copyright 2026 Fibratus contributors
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

package spike

import (
	"fmt"
	"os"
	"strings"
)

// enrichFromProc best-effort reads /proc/<pid>/{exe,cmdline}. Failures leave
// fields empty and never replace the iterator baseline scan.
func enrichFromProc(pid uint32) (exe string, cmdline string, err error) {
	exeLink := fmt.Sprintf("/proc/%d/exe", pid)
	exe, err = os.Readlink(exeLink)
	if err != nil {
		exe = ""
	}

	raw, cerr := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if cerr != nil {
		if err == nil {
			err = cerr
		}
		return exe, "", err
	}
	parts := strings.Split(string(raw), "\x00")
	var cleaned []string
	for _, p := range parts {
		if p != "" {
			cleaned = append(cleaned, p)
		}
	}
	return exe, strings.Join(cleaned, " "), err
}

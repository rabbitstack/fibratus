//go:build linux

/*
 * Copyright 2026 by Mostafa Moradian
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

package ebpf

import (
	"strings"

	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
)

func snapshotFromRaw(r rawEvent, exe, cmdline string) *pstypes.PS {
	name := r.comm()
	if name == "" && exe != "" {
		name = baseName(exe)
	}
	if cmdline == "" {
		cmdline = exe
	}
	args := splitCmdline(cmdline)
	return &pstypes.PS{
		PID:           uint64(r.TGID),
		Ppid:          uint64(r.PPID),
		Name:          name,
		Cmdline:       cmdline,
		Exe:           exe,
		Args:          args,
		StartBootTime: r.StartBootTime,
		UID:           r.UID,
		GID:           r.GID,
		Threads:       make(map[uint64]pstypes.Thread),
	}
}

func baseName(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 && i+1 < len(path) {
		return path[i+1:]
	}
	return path
}

func splitCmdline(cmdline string) []string {
	if cmdline == "" {
		return nil
	}
	return strings.Fields(cmdline)
}

/*
 * Copyright 2019-2026 by Nedim Sabic Sabic
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

package probe

import (
	"path/filepath"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/filter/ql"
	"github.com/rabbitstack/fibratus/pkg/util/wildcard"
	"golang.org/x/sys/windows"
)

func (p *Probe) isFilePathApproved(path string, disposition uint32) bool {
	if p.rs == nil || len(p.rs.Approvers.Paths) == 0 {
		return true
	}

	if disposition != windows.FILE_OPEN {
		return true
	}

	return p.matchesApprover(p.rs.Approvers.Paths, path)
}

func (p *Probe) isFileBaseApproved(path string, disposition uint32) bool {
	if p.rs == nil || len(p.rs.Approvers.Bases) == 0 {
		return true
	}

	if disposition != windows.FILE_OPEN {
		return true
	}

	return p.matchesApprover(p.rs.Approvers.Bases, filepath.Base(path))
}

func (p *Probe) isFileExtApproved(path string, disposition uint32) bool {
	if p.rs == nil || len(p.rs.Approvers.Extensions) == 0 {
		return true
	}

	if disposition != windows.FILE_OPEN {
		return true
	}

	return p.matchesApprover(p.rs.Approvers.Extensions, filepath.Ext(path))
}

func (p *Probe) isRegPathApproved(path string) bool {
	if p.rs == nil || len(p.rs.Approvers.Keys) == 0 {
		return true
	}

	return p.matchesApprover(p.rs.Approvers.Keys, path)
}

func (p *Probe) isExecutablePathApproved(pid uint32, remote bool) bool {
	if p.rs == nil || len(p.rs.Approvers.Executables) == 0 {
		return true
	}

	if remote {
		return true
	}

	// Attempt to find the target process iin the snapshotter state and pass
	// the executable path to the approver. If we can't find the process in the
	// snapshotter or the executable path is not resolved, the event is approved
	ok, ps := p.psnap.Find(pid)
	if !ok || ps == nil || ps.Exe == "" {
		return true
	}

	return p.matchesApprover(p.rs.Approvers.Executables, ps.Exe)
}

func (*Probe) matchesApprover(m map[string][]string, v string) bool {
	for op, patterns := range m {
		for _, pattern := range patterns {
			switch op {
			case ql.IMatches.String():
				if wildcard.Match(pattern, v, false) {
					return true
				}
			case ql.IContains.String():
				if strings.Contains(strings.ToLower(v), pattern) {
					return true
				}
			case ql.Eq.String(), ql.In.String():
				return v == pattern
			case ql.IEq.String(), ql.IIn.String():
				return strings.EqualFold(v, pattern)
			case ql.IStartswith.String():
				return strings.HasPrefix(strings.ToLower(v), pattern)
			case ql.IEndswith.String():
				return strings.HasSuffix(strings.ToLower(v), pattern)
			}
		}
	}
	return false
}

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

package filter

import (
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/rabbitstack/fibratus/pkg/ps"
)

// GetAccessors returns the accessors available on Linux.
func GetAccessors() []Accessor {
	return []Accessor{
		newEventAccessor(),
		newPSAccessor(nil),
	}
}

type psAccessor struct {
	psnap ps.Snapshotter
}

func (psAccessor) SetFields([]Field)            {}
func (psAccessor) SetSegments([]fields.Segment) {}
func (psAccessor) IsFieldAccessible(e *event.Event) bool {
	return e.PS != nil || e.Category == event.Process
}

func newPSAccessor(psnap ps.Snapshotter) Accessor { return &psAccessor{psnap: psnap} }

func (a *psAccessor) Get(f Field, e *event.Event) (params.Value, error) {
	switch f.Name {
	case fields.PsPid:
		return e.PID, nil
	case fields.PsPpid:
		if e.PS == nil {
			return nil, ErrPsNil
		}
		return e.PS.Ppid, nil
	case fields.PsName:
		if e.PS == nil {
			return nil, ErrPsNil
		}
		return e.PS.Name, nil
	case fields.PsComm, fields.PsCmdline:
		if e.PS == nil {
			return nil, ErrPsNil
		}
		return e.PS.Cmdline, nil
	case fields.PsExe:
		if e.PS == nil {
			return nil, ErrPsNil
		}
		return e.PS.Exe, nil
	case fields.PsArgs:
		if e.PS == nil {
			return nil, ErrPsNil
		}
		return e.PS.Args, nil
	case fields.PsCwd:
		if e.PS == nil {
			return nil, ErrPsNil
		}
		return e.PS.Cwd, nil
	case fields.PsUsername:
		if e.PS == nil {
			return nil, ErrPsNil
		}
		return e.PS.Username, nil
	case fields.PsEnvs:
		if e.PS == nil {
			return nil, ErrPsNil
		}
		return e.PS.Envs, nil
	case fields.PsParentPid:
		if e.PS == nil || e.PS.Parent == nil {
			return nil, ErrPsNil
		}
		return e.PS.Parent.PID, nil
	case fields.PsParentName:
		if e.PS == nil || e.PS.Parent == nil {
			return nil, ErrPsNil
		}
		return e.PS.Parent.Name, nil
	case fields.PsParentCmdline:
		if e.PS == nil || e.PS.Parent == nil {
			return nil, ErrPsNil
		}
		return e.PS.Parent.Cmdline, nil
	case fields.PsParentExe:
		if e.PS == nil || e.PS.Parent == nil {
			return nil, ErrPsNil
		}
		return e.PS.Parent.Exe, nil
	default:
		return nil, nil
	}
}

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

package fields

import "github.com/rabbitstack/fibratus/pkg/event/params"

func platformString() params.Type     { return params.String }
func platformAnsiString() params.Type { return params.String }

var fields = platformFields(map[Field]FieldInfo{
	EvtPID:      {EvtPID, "process identifier generating the event", params.Uint64, []string{"evt.pid = 6"}, nil, nil},
	EvtTID:      {EvtTID, "thread identifier generating the event", params.Uint64, []string{"evt.tid = 1024"}, nil, nil},
	PsPid:       {PsPid, "process identifier", params.Uint64, []string{"ps.pid = 1024"}, nil, nil},
	PsPpid:      {PsPpid, "parent process identifier", params.Uint64, []string{"ps.ppid = 45"}, nil, nil},
	PsParentPid: {PsParentPid, "parent process id", params.Uint64, []string{"ps.parent.pid = 4"}, nil, nil},
})

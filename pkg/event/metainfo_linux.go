//go:build linux

/*
 * Copyright 2026 by Nedim Sabic Sabic
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

package event

import "slices"

type Info struct {
	Name        string
	Category    Category
	Description string
}

var events = map[Type]Info{
	CreateProcess:    {Name: "CreateProcess", Category: Process, Description: "Creates a new process"},
	Execve:           {Name: "Execve", Category: Process, Description: "Executes a program"},
	TerminateProcess: {Name: "TerminateProcess", Category: Process, Description: "Terminates a process"},
	Exit:             {Name: "Exit", Category: Process, Description: "Exits a process"},
	ProcessRundown:   {Name: "ProcessRundown", Category: Process, Description: "Reports an existing process"},
	Clone:            {Name: "Clone", Category: Process, Description: "Clones a process or thread"},
}

var types = map[string]Type{
	"CreateProcess":    CreateProcess,
	"Execve":           Execve,
	"TerminateProcess": TerminateProcess,
	"Exit":             Exit,
	"ProcessRundown":   ProcessRundown,
	"Clone":            Clone,
}

func All() []Type {
	return []Type{CreateProcess, Execve, TerminateProcess, Exit, Clone}
}

func AllWithState() []Type {
	return append(All(), ProcessRundown)
}

func MaxTypeID() uint16 {
	return uint16(slices.Max(AllWithState()))
}

func TypeToEventInfo(typ Type) Info {
	if info, ok := events[typ]; ok {
		return info
	}
	return Info{Name: "N/A", Category: Unknown}
}

func NameToType(name string) Type {
	if typ, ok := types[name]; ok {
		return typ
	}
	return UnknownType
}

func NameToTypes(name string) []Type {
	return []Type{NameToType(name)}
}

func GetTypesMeta() []Info {
	infos := make([]Info, 0, len(events))
	for _, info := range events {
		infos = append(infos, info)
	}
	slices.SortFunc(infos, func(a, b Info) int {
		if a.Category == b.Category {
			if a.Name < b.Name {
				return -1
			}
			if a.Name > b.Name {
				return 1
			}
			return 0
		}
		if a.Category < b.Category {
			return -1
		}
		return 1
	})
	return infos
}

func GetTypesMetaIndexed() []Info {
	return GetTypesMeta()
}

func IsKnown(name string) bool {
	return NameToType(name) != UnknownType
}

/*
 * Copyright 2020-2021 by Nedim Sabic Sabic
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

import (
	"sort"

	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
)

const (
	// KevtSeq is the event sequence number
	KevtSeq Field = "kevt.seq"
	// KevtPID is the process identifier that generated the event
	KevtPID Field = "kevt.pid"
	// KevtTID is the thread identifier that generated the event
	KevtTID Field = "kevt.tid"
	// KevtCPU is the CPU core where the event was generated
	KevtCPU Field = "kevt.cpu"
	// KevtDesc represents the event description
	KevtDesc Field = "kevt.desc"
	// KevtHost represents the host where the event was produced
	KevtHost Field = "kevt.host"
	// KevtTime is the event time
	KevtTime Field = "kevt.time"
	// KevtTimeHour is the hour part of the event time
	KevtTimeHour Field = "kevt.time.h"
	// KevtTimeMin is the minute part of the event time
	KevtTimeMin Field = "kevt.time.m"
	// KevtTimeSec is the second part of the event time
	KevtTimeSec Field = "kevt.time.s"
	// KevtTimeNs is the nanosecond part of the event time
	KevtTimeNs Field = "kevt.time.ns"
	// KevtDate is the event date
	KevtDate Field = "kevt.date"
	// KevtDateDay is the day of event date
	KevtDateDay Field = "kevt.date.d"
	// KevtDateMonth is the month of event date
	KevtDateMonth Field = "kevt.date.m"
	// KevtDateYear is the year of event date
	KevtDateYear Field = "kevt.date.y"
	// KevtDateTz is the time zone of event timestamp
	KevtDateTz Field = "kevt.date.tz"
	// KevtDateWeek is the event week number
	KevtDateWeek Field = "kevt.date.week"
	// KevtDateWeekday is the event week day
	KevtDateWeekday Field = "kevt.date.weekday"
	// KevtName is the event name
	KevtName Field = "kevt.name"
	// KevtCategory is the event category
	KevtCategory Field = "kevt.category"
	// KevtMeta is the event metadata
	KevtMeta Field = "kevt.meta"
	// KevtNparams is the number of event parameters
	KevtNparams Field = "kevt.nparams"
)

// Field represents the type alias for the field
type Field string

// String casts the field type to string.
func (f Field) String() string { return string(f) }

// FieldInfo is the field metadata descriptor.
type FieldInfo struct {
	Field    Field
	Desc     string
	Type     kparams.Type
	Examples []string
}

// Get returns a slice of field information.
func Get() []FieldInfo {
	fi := make([]FieldInfo, 0, len(fields))
	for _, field := range fields {
		fi = append(fi, field)
	}
	sort.Slice(fi, func(i, j int) bool { return fi[i].Field < fi[j].Field })
	return fi
}

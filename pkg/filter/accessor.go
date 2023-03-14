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

package filter

import (
	"errors"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
)

var (
	// ErrPsNil indicates the process state associated with the event is not initialized
	ErrPsNil = errors.New("process state is nil")
)

// kevtAccessor extracts generic event values.
type kevtAccessor struct{}

func (k *kevtAccessor) canAccess(kevt *kevent.Kevent, filter *filter) bool {
	return true
}

func newKevtAccessor() accessor {
	return &kevtAccessor{}
}

const timeFmt = "15:04:05"
const dateFmt = "2006-01-02"

func (k *kevtAccessor) get(f fields.Field, kevt *kevent.Kevent) (kparams.Value, error) {
	switch f {
	case fields.KevtSeq:
		return kevt.Seq, nil
	case fields.KevtPID:
		return kevt.PID, nil
	case fields.KevtTID:
		return kevt.Tid, nil
	case fields.KevtCPU:
		return kevt.CPU, nil
	case fields.KevtName:
		return kevt.Name, nil
	case fields.KevtCategory:
		return string(kevt.Category), nil
	case fields.KevtDesc:
		return kevt.Description, nil
	case fields.KevtHost:
		return kevt.Host, nil
	case fields.KevtTime:
		return kevt.Timestamp.Format(timeFmt), nil
	case fields.KevtTimeHour:
		return uint8(kevt.Timestamp.Hour()), nil
	case fields.KevtTimeMin:
		return uint8(kevt.Timestamp.Minute()), nil
	case fields.KevtTimeSec:
		return uint8(kevt.Timestamp.Second()), nil
	case fields.KevtTimeNs:
		return kevt.Timestamp.UnixNano(), nil
	case fields.KevtDate:
		return kevt.Timestamp.Format(dateFmt), nil
	case fields.KevtDateDay:
		return uint8(kevt.Timestamp.Day()), nil
	case fields.KevtDateMonth:
		return uint8(kevt.Timestamp.Month()), nil
	case fields.KevtDateTz:
		tz, _ := kevt.Timestamp.Zone()
		return tz, nil
	case fields.KevtDateYear:
		return uint32(kevt.Timestamp.Year()), nil
	case fields.KevtDateWeek:
		_, week := kevt.Timestamp.ISOWeek()
		return uint8(week), nil
	case fields.KevtDateWeekday:
		return kevt.Timestamp.Weekday().String(), nil
	case fields.KevtNparams:
		return uint64(kevt.Kparams.Len()), nil
	default:
		if f.IsKevtArgMap() {
			name, _ := captureInBrackets(f.String())
			return kevt.Kparams.Get(name)
		}
		return nil, nil
	}
}

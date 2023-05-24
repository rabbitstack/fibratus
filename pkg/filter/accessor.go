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
	"reflect"
)

var (
	// ErrPsNil indicates the process state associated with the event is not initialized
	ErrPsNil = errors.New("process state is nil")
)

// kevtAccessor extracts generic event values.
type kevtAccessor struct{}

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
			kpar, err := kevt.Kparams.Get(name)
			if err != nil {
				return nil, err
			}
			switch kpar.Type {
			case kparams.Uint8:
				return kevt.Kparams.GetUint8(name)
			case kparams.Uint16, kparams.Port:
				return kevt.Kparams.GetUint16(name)
			case kparams.Uint32, kparams.PID, kparams.TID:
				return kevt.Kparams.GetUint32(name)
			case kparams.Uint64:
				return kevt.Kparams.GetUint64(name)
			case kparams.Time:
				return kevt.Kparams.GetTime(name)
			default:
				return kevt.GetParamAsString(name), nil
			}
		}
		return nil, nil
	}
}

// narrowAccessors dynamically disables filter accessors by walking
// the fields declared in the expression. The field can be expressed
// as a regular LHS/RHS component, used as a function parameter or
// referenced in the bound field.
func (f *filter) narrowAccessors() {
	var (
		removeKevtAccessor     = true
		removePsAccessor       = true
		removeThreadAccessor   = true
		removeImageAccessor    = true
		removeFileAccessor     = true
		removeRegistryAccessor = true
		removeNetworkAccessor  = true
		removeHandleAccessor   = true
		removePEAccessor       = true
	)
	allFields := make([]fields.Field, 0)
	allFields = append(allFields, f.fields...)
	for _, field := range f.boundFields {
		allFields = append(allFields, field.Field())
	}
	for _, field := range allFields {
		switch {
		case field.IsKevtField():
			removeKevtAccessor = false
		case field.IsPsField():
			removePsAccessor = false
		case field.IsThreadField():
			removeThreadAccessor = false
		case field.IsImageField():
			removeImageAccessor = false
		case field.IsFileField():
			removeFileAccessor = false
		case field.IsRegistryField():
			removeRegistryAccessor = false
		case field.IsNetworkField():
			removeNetworkAccessor = false
		case field.IsHandleField():
			removeHandleAccessor = false
		case field.IsPeField():
			removePEAccessor = false
		}
	}
	if removeKevtAccessor {
		f.removeAccessor(&kevtAccessor{})
	}
	if removePsAccessor {
		f.removeAccessor(&psAccessor{})
	}
	if removeThreadAccessor {
		f.removeAccessor(&threadAccessor{})
	}
	if removeImageAccessor {
		f.removeAccessor(&imageAccessor{})
	}
	if removeFileAccessor {
		f.removeAccessor(&fileAccessor{})
	}
	if removeRegistryAccessor {
		f.removeAccessor(&registryAccessor{})
	}
	if removeNetworkAccessor {
		f.removeAccessor(&networkAccessor{})
	}
	if removeHandleAccessor {
		f.removeAccessor(&handleAccessor{})
	}
	if removePEAccessor {
		f.removeAccessor(&peAccessor{})
	}
}

func (f *filter) removeAccessor(removed accessor) {
	for i, accessor := range f.accessors {
		if reflect.TypeOf(accessor) == reflect.TypeOf(removed) {
			f.accessors = append(f.accessors[:i], f.accessors[i+1:]...)
		}
	}
}

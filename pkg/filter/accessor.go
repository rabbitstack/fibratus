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
	"net"
	"reflect"
	"time"

	"github.com/rabbitstack/fibratus/internal/evasion"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
)

var (
	// ErrPsNil indicates the process state associated with the event is not initialized
	ErrPsNil = errors.New("process state is nil")
)

// Accessor dictates the behaviour of the field accessors. One of the main responsibilities of the accessor is
// to extract the underlying parameter for the field given in the filter expression. It can also produce a value
// from the non-params constructs such as process' state or PE metadata.
type Accessor interface {
	// Get fetches the parameter value for the specified filter field.
	Get(f Field, evt *event.Event) (params.Value, error)
	// SetFields sets all fields declared in the expression.
	SetFields(fields []Field)
	// SetSegments sets all segments utilized in the function predicate expression.
	SetSegments(segments []fields.Segment)
	// IsFieldAccessible determines if the field can be extracted from the
	// given event. The condition is usually based on the event category,
	// but it can also include different circumstances, like the presence
	// of the process state or callstacks.
	IsFieldAccessible(evt *event.Event) bool
}

// evtAccessor extracts generic event values.
type evtAccessor struct{}

func (evtAccessor) SetFields([]Field)                   {}
func (evtAccessor) SetSegments([]fields.Segment)        {}
func (evtAccessor) IsFieldAccessible(*event.Event) bool { return true }

func newEventAccessor() Accessor {
	return &evtAccessor{}
}

const timeFmt = "15:04:05"
const dateFmt = "2006-01-02"

func (*evtAccessor) Get(f Field, evt *event.Event) (params.Value, error) {
	switch f.Name {
	case fields.EvtSeq, fields.KevtSeq:
		return evt.Seq, nil
	case fields.EvtPID, fields.KevtPID:
		return evt.PID, nil
	case fields.EvtTID, fields.KevtTID:
		return evt.Tid, nil
	case fields.EvtCPU, fields.KevtCPU:
		return evt.CPU, nil
	case fields.EvtName, fields.KevtName:
		return evt.Name, nil
	case fields.EvtCategory, fields.KevtCategory:
		return string(evt.Category), nil
	case fields.EvtDesc, fields.KevtDesc:
		return evt.Description, nil
	case fields.EvtHost, fields.KevtHost:
		return evt.Host, nil
	case fields.EvtTime, fields.KevtTime:
		return evt.Timestamp.Format(timeFmt), nil
	case fields.EvtTimeHour, fields.KevtTimeHour:
		return uint8(evt.Timestamp.Hour()), nil
	case fields.EvtTimeMin, fields.KevtTimeMin:
		return uint8(evt.Timestamp.Minute()), nil
	case fields.EvtTimeSec, fields.KevtTimeSec:
		return uint8(evt.Timestamp.Second()), nil
	case fields.EvtTimeNs, fields.KevtTimeNs:
		return evt.Timestamp.UnixNano(), nil
	case fields.EvtDate, fields.KevtDate:
		return evt.Timestamp.Format(dateFmt), nil
	case fields.EvtDateDay, fields.KevtDateDay:
		return uint8(evt.Timestamp.Day()), nil
	case fields.EvtDateMonth, fields.KevtDateMonth:
		return uint8(evt.Timestamp.Month()), nil
	case fields.EvtDateTz, fields.KevtDateTz:
		tz, _ := evt.Timestamp.Zone()
		return tz, nil
	case fields.EvtDateYear, fields.KevtDateYear:
		return uint32(evt.Timestamp.Year()), nil
	case fields.EvtDateWeek, fields.KevtDateWeek:
		_, week := evt.Timestamp.ISOWeek()
		return uint8(week), nil
	case fields.EvtDateWeekday, fields.KevtDateWeekday:
		return evt.Timestamp.Weekday().String(), nil
	case fields.EvtNparams, fields.KevtNparams:
		return uint64(evt.Params.Len()), nil
	case fields.EvtArg, fields.KevtArg:
		// lookup the parameter from the field argument
		// and depending on the parameter type, return
		// the respective value. The field format is
		// expressed as evt.arg[cmdline] where the string
		// inside brackets represents the parameter name
		name := f.Arg
		par, err := evt.Params.Get(name)
		if err != nil {
			return nil, err
		}

		switch par.Type {
		case params.Uint8:
			return evt.Params.GetUint8(name)
		case params.Uint16, params.Port:
			return evt.Params.GetUint16(name)
		case params.Uint32, params.PID, params.TID:
			return evt.Params.GetUint32(name)
		case params.Uint64:
			return evt.Params.GetUint64(name)
		case params.Time:
			return evt.Params.GetTime(name)
		default:
			return evt.GetParamAsString(name), nil
		}
	case fields.EvtIsDirectSyscall:
		return evt.Evasions&uint32(evasion.DirectSyscall) != 0, nil
	case fields.EvtIsIndirectSyscall:
		return evt.Evasions&uint32(evasion.IndirectSyscall) != 0, nil
	}

	return nil, nil
}

// narrowAccessors dynamically disables filter accessors by walking
// the fields declared in the expression. The field can be expressed
// as a regular LHS/RHS component, used as a function parameter or
// referenced in the bound field.
func (f *filter) narrowAccessors() {
	var (
		removeEvtAccessor        = true
		removePsAccessor         = true
		removeThreadAccessor     = true
		removeImageAccessor      = true
		removeFileAccessor       = true
		removeRegistryAccessor   = true
		removeNetworkAccessor    = true
		removeHandleAccessor     = true
		removePEAccessor         = true
		removeMemAccessor        = true
		removeDNSAccessor        = true
		removeThreadpoolAccessor = true
	)

	for _, field := range f.fields {
		switch {
		case field.Name.IsKevtField(), field.Name.IsEvtField():
			removeEvtAccessor = false
		case field.Name.IsPsField():
			removePsAccessor = false
		case field.Name.IsThreadField():
			removeThreadAccessor = false
		case field.Name.IsImageField():
			removeImageAccessor = false
		case field.Name.IsFileField():
			removeFileAccessor = false
		case field.Name.IsRegistryField():
			removeRegistryAccessor = false
		case field.Name.IsNetworkField():
			removeNetworkAccessor = false
		case field.Name.IsHandleField():
			removeHandleAccessor = false
		case field.Name.IsPeField():
			removePEAccessor = false
		case field.Name.IsMemField():
			removeMemAccessor = false
		case field.Name.IsDNSField():
			removeDNSAccessor = false
		case field.Name.IsThreadpoolField():
			removeThreadpoolAccessor = false
		}
	}

	if removeEvtAccessor {
		f.removeAccessor(&evtAccessor{})
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
	if removeMemAccessor {
		f.removeAccessor(&memAccessor{})
	}
	if removeDNSAccessor {
		f.removeAccessor(&dnsAccessor{})
	}
	if removeThreadpoolAccessor {
		f.removeAccessor(&threadpoolAccessor{})
	}

	for _, accessor := range f.accessors {
		accessor.SetFields(f.fields)
		accessor.SetSegments(f.segments)
	}
}

func (f *filter) removeAccessor(removed Accessor) {
	for i, accessor := range f.accessors {
		if reflect.TypeOf(accessor) == reflect.TypeOf(removed) {
			f.accessors = append(f.accessors[:i], f.accessors[i+1:]...)
		}
	}
}

var (
	zeroTime  time.Time
	zeroSlice []string
	zeroIP    net.IP
	zeroByte  []byte
)

// defaultAccessorValue provides the default value for the field.
// This value is typically assigned when the accessor returns an
// error or nil value, but the map valuer must contain the resolved
// field name in case of filters using the not operator.
func defaultAccessorValue(field Field) any {
	switch field.Name.Type() {
	case params.Uint8, params.Int64, params.Int8, params.Int32, params.Int16,
		params.Uint16, params.Port, params.Uint32, params.Uint64, params.PID,
		params.TID, params.Flags, params.Flags64:
		return 0
	case params.Float, params.Double:
		return 0.0
	case params.Time:
		return zeroTime
	case params.Bool:
		return false
	case params.IP, params.IPv4, params.IPv6:
		return zeroIP
	case params.Binary:
		return zeroByte
	case params.Slice:
		return zeroSlice
	default:
		return ""
	}
}

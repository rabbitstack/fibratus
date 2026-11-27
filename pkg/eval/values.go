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

package eval

import (
	"net"
	"time"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
)

const timeFmt = "15:04:05"
const dateFmt = "2006-01-02"

// param returns the value of the named event parameter extracted by the getter,
// or the zero value if the event doesn't have the parameter.
func param[T any](e *event.Event, name string, get func(event.Params, string) T) T {
	if !e.Params.Contains(name) {
		var zero T
		return zero
	}
	return get(e.Params, name)
}

var (
	zeroTime  time.Time
	zeroSlice []string
	zeroIP    net.IP
	zeroByte  []byte
)

// defaultValue provides the default value for the field. It is the value of a
// field the event has no value for: the source of the field can't serve the
// event, or the evaluator reports there is none. The map valuer must contain
// the field even then, since the filters using the not operator look it up.
func defaultValue(field Field) any {
	switch field.Name.Type() {
	case params.Uint8, params.Int64, params.Int8, params.Int32, params.Int16,
		params.Uint16, params.Port, params.Uint32, params.Uint64, params.PID,
		params.TID, params.Flags32, params.Flags64:
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

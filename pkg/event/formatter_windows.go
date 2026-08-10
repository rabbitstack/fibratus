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

package event

import (
	"fmt"

	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/util/colorizer"
)

func addPlatformFormatValues(evt *Event, values map[string]interface{}) {
	if !evt.Callstack.IsEmpty() {
		values[cstack] = evt.Callstack.String()
	}
}

func addPlatformProcessFormatValues(ps *pstypes.PS, values map[string]interface{}) {
	values[sid] = ps.SID
	if ps.PE != nil {
		values[pe] = ps.PE.String()
	}
}

func colourPlatformTag(_ string, evt *Event) string {
	return fmt.Sprintf("\n%s", evt.Callstack.Colorize())
}

func colourPlatformProcessTag(tag string, evt *Event) (string, bool) {
	switch tag {
	case sid:
		if evt.PS == nil {
			return colorizer.Span(colorizer.Gray, "N/A"), true
		}
		return colorizer.Span(colorizer.Gray, evt.PS.SID), true
	case pe:
		if evt.PS == nil || evt.PS.PE == nil {
			return colorizer.Span(colorizer.Gray, "N/A"), true
		}
		return colorizer.Span(colorizer.Magenta, evt.PS.PE.String()), true
	default:
		return "", false
	}
}

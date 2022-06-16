//go:build windows
// +build windows

/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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

package filetime

import (
	"time"
)

// ToEpoch converts file timestamp to Unix time.
func ToEpoch(ts uint64) time.Time { return time.Unix(0, nanoseconds(ts)) }

// nanoseconds returns Filetime ft in nanoseconds
// since Epoch (00:00:00 UTC, January 1, 1970). This
// function is copied from the stdlib to avoid allocating
// the FileTime structure in the `ToEpoch` function.
func nanoseconds(ts uint64) int64 {
	// 100-nanosecond intervals since January 1, 1601
	nsec := int64(uint32(ts>>32))<<32 + int64(uint32(ts))
	// change starting time to the Epoch (00:00:00 UTC, January 1, 1970)
	nsec -= 116444736000000000
	// convert into nanoseconds
	nsec *= 100
	return nsec
}

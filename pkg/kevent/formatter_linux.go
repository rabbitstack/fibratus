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

package kevent

import "strconv"

func (f *Formatter) Format(kevt *Kevent) []byte {
	if kevt == nil {
		return []byte{}
	}
	values := map[string]interface{}{
		ts:          kevt.Timestamp.String(),
		pid:         strconv.FormatUint(uint64(kevt.PID), 10),
		tid:         strconv.FormatUint(uint64(kevt.Tid), 10),
		seq:         strconv.FormatUint(kevt.Seq, 10),
		cpu:         strconv.FormatUint(uint64(kevt.CPU), 10),
		typ:         kevt.Name,
		cat:         kevt.Category,
		desc:        kevt.Description,
		host:        kevt.Host,
		meta:        kevt.Metadata.String(),
		kparameters: kevt.Kparams.String(),
	}

	return f.t.ExecuteString(values)
}

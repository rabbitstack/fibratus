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

package filter

func (f *filter) pruneUnusedAccessors() {
	removeEvtAccessor := true
	removePsAccessor := true

	for _, field := range f.fields {
		switch {
		case field.Name.IsEvtField() || field.Name.IsKevtField():
			removeEvtAccessor = false
		case field.Name.IsPsField():
			removePsAccessor = false
		}
	}

	if removeEvtAccessor {
		f.removeAccessor(&evtAccessor{})
	}
	if removePsAccessor {
		f.removeAccessor(&psAccessor{})
	}
}

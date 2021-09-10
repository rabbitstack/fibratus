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

package ktypes

import "github.com/rabbitstack/fibratus/pkg/kevent/kparams"

// KeventInfo describes the kernel event meta info such as human readable name, category
// and event's description.
type KeventInfo struct {
	// Name is the human-readable representation of the kernel event (e.g. CreateProcess, DeleteFile).
	Name string
	// Category designates the category to which kernel event pertains. (e.g. process, net)
	Category Category
	// Description is the short explanation that describes the purpose of the kernel event.
	Description string
	// Kpars describes event parameters information.
	Kpars []KparInfo
}

// KparInfo describes each of the parameters captured in kernel tracepoint.
type KparInfo struct {
	Name string       // parameter name, such as fd
	Type kparams.Type // parameter type, such as int64
}

var kevents = map[Ktype]KeventInfo{
	Read: {"read", File, "reads data from a file descriptor", []KparInfo{}},
}

var ktypes = map[string]Ktype{
	"read": Read,
}

// GetKtypesMap returns the map of available ktypes.
func GetKtypesMap() map[string]Ktype { return ktypes }

// KtypeToKeventInfo derives event metainfo from its type.
func KtypeToKeventInfo(ktype Ktype) KeventInfo {
	if kinfo, ok := kevents[ktype]; ok {
		return kinfo
	}
	return KeventInfo{Name: "N/A", Category: Unknown}
}

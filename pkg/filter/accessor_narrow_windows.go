//go:build windows

/*
 * Copyright 2020-2021 by Nedim Sabic Sabic
 * Copyright 2026 by Mostafa Moradian
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
	var (
		removeEvtAccessor        = true
		removePsAccessor         = true
		removeThreadAccessor     = true
		removeModuleAccessor     = true
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
		case field.Name.IsEvtField() || field.Name.IsKevtField():
			removeEvtAccessor = false
		case field.Name.IsPeField():
			removePEAccessor = false
		case field.Name.IsPsField():
			removePsAccessor = false
		case field.Name.IsThreadField():
			removeThreadAccessor = false
		case field.Name.IsImageField() || field.Name.IsModuleField():
			removeModuleAccessor = false
		case field.Name.IsFileField():
			removeFileAccessor = false
		case field.Name.IsRegistryField():
			removeRegistryAccessor = false
		case field.Name.IsNetworkField():
			removeNetworkAccessor = false
		case field.Name.IsHandleField():
			removeHandleAccessor = false
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
	if removeModuleAccessor {
		f.removeAccessor(&moduleAccessor{})
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
}

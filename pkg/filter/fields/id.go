/*
 * Copyright 2016-present by Nedim Sabic Sabic
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

package fields

const MaxFieldID int16 = 23

// ID returns the filter index used by the valuer cache.
// Note that not all fields need to provide the identifier.
func (f Field) ID() int16 {
	switch f {
	case EvtName:
		return 0
	case EvtPID:
		return 1
	case RegistryPath:
		return 2
	case FilePath:
		return 3
	case FileExtension:
		return 4
	case PsExe:
		return 5
	case PsName:
		return 6
	case PsPid:
		return 7
	case FileOperation:
		return 8
	case FileStatus:
		return 9
	case RegistryStatus:
		return 10
	case ModuleName:
		return 11
	case ModulePath:
		return 12
	case ModuleSignatureExists, DllSignatureExists:
		return 13
	case ModuleSignatureTrusted, DllSignatureTrusted:
		return 14
	case ThreadCallstackSummary:
		return 15
	case ThreadCallstackModules:
		return 16
	case ThreadCallstackSymbols:
		return 17
	case PsParentName:
		return 18
	case PsSID:
		return 19
	case PsCmdline:
		return 20
	case PsTokenIntegrityLevel:
		return 21
	case PsAccessMaskNames:
		return MaxFieldID - 1
	}
	return -1
}

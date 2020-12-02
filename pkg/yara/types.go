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

package yara

// Scanner watches for certain kernel events such as process creation or image loading and
// triggers the scanning either of the target process or image file. If matches occur, an
// alert is emitted via specified alert sender.
type Scanner interface {
	// ScanProc scans process memory.
	ScanProc(pid uint32) error
	// ScanFile scans the specified file in the file system.
	ScanFile(filename string) error
	// Close disposes any resources allocated by scanner.
	Close()
}

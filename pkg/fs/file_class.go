/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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

package fs

// FileInfoClasses contains the values that specify which structure to use to query or set information for a file object.
// For more information see https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_file_information_class
var FileInfoClasses = map[uint32]string{
	1:  "Directory",
	2:  "Full Directory",
	3:  "Both Directory",
	4:  "Basic",
	5:  "Standard",
	6:  "Internal",
	7:  "EA",
	8:  "Access",
	9:  "Name",
	10: "Rename",
	11: "Link",
	12: "Names",
	13: "Disposition",
	14: "Position",
	15: "Full EA",
	16: "Mode",
	17: "Alignment",
	18: "All",
	19: "Allocation",
	20: "EOF",
	21: "Alternative Name",
	22: "Stream",
	23: "Pipe",
	24: "Pipe Local",
	25: "Pipe Remote",
	26: "Mailslot Query",
	27: "Mailslot Set",
	28: "Compression",
	29: "Object ID",
	30: "Completion",
	31: "Move Cluster",
	32: "Quota",
	33: "Reparse Point",
	34: "Network Open",
	35: "Attribute Tag",
	36: "Tracking",
	37: "ID Both Directory",
	38: "ID Full Directory",
	39: "Valid Data Length",
	40: "Short Name",
	41: "IO Completion Notification",
	42: "IO Status Block Range",
	43: "IO Priority Hint",
	44: "Sfio Reserve",
	45: "Sfio Volume",
	46: "Hard Link",
	47: "Process IDS Using File",
	48: "Normalized Name",
	49: "Network Physical Name",
	50: "ID Global Tx Directory",
	51: "Is Remote Device",
	52: "Unused",
	53: "Numa Node",
	54: "Standard Link",
	55: "Remote Protocol",
	56: "Rename Bypass Access Check",
	57: "Link Bypass Access Check",
	58: "Volume Name",
	59: "ID",
	60: "ID Extended Directory",
	61: "Replace Completion",
	62: "Hard Link Full ID",
	63: "ID Extended Both Directory",
	64: "Disposition Extended",
	65: "Rename Extended",
	66: "Rename Extended Bypass Access Check",
	67: "Desired Storage",
	68: "Stat",
	69: "Memory Partition",
	70: "Stat LX",
	71: "Case Sensitive",
	72: "Link Extended",
	73: "Link Extended Bypass Access Check",
	74: "Storage Reserve ID",
	75: "Case Sensitive Force Access Check",
}

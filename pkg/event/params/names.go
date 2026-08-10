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

package params

const (
	// ProcessID represents the process identifier.
	ProcessID = "pid"
	// TargetProcessID represents the target process identifier.
	TargetProcessID = "target_pid"
	// ThreadID field represents the thread identifier.
	ThreadID = "tid"
	// ProcessParentID field represents the parent process identifier.
	ProcessParentID = "ppid"
	// SessionID fields represents the session identifier.
	SessionID = "session_id"
	// Username field represents the username under which the event was generated.
	Username = "username"
	// ProcessName field denotes the process Module name.
	ProcessName = "name"
	// Exe field denotes the full path of the executable.
	Exe = "exe"
	// Cmdline field represents the process command line.
	Cmdline = "cmdline"
	// ProcessFlags field denotes the process creation flags
	ProcessFlags = "flags"
	// ExitStatus is the field that represents the process exit status.
	ExitStatus = "exit_status"
	// StartTime field denotes the process start time.
	StartTime = "start_time"
	// FileObject determines the field name for the file object pointer.
	FileObject = "file_object"
	// FilePath represents the field that designates the absolute path of the file.
	FilePath = "file_path"
	// FileCreated represents the name for the file creation field.
	FileCreated = "created"
	// FileAccessed represents the name for the file access field.
	FileAccessed = "accessed"
	// FileModified represents the name for the file modification field.
	FileModified = "modified"
	// FileType represents the field name that indicates the file type.
	FileType = "type"
	// FileIoSize is the filed that represents the number of bytes in file read/write operations.
	FileIoSize = "io_size"
	// FileOffset represents the file for the file offset in read/write operations.
	FileOffset = "offset"
	// FileKey represents the directory key identifier in EnumDirectory events.
	FileKey = "file_key"
	// FileDirectory represents the field for the directory name in EnumDirectory events.
	FileDirectory = "directory"
	// FileExtraInfo is the parameter that represents extra information returned by the file system for the operation. For example for a read request, the actual number of bytes that were read.
	FileExtraInfo = "extra_info"
	// FileIsExecutable is the parameter that indicates if the file is an executable
	FileIsExecutable = "is_exec"

	// FileViewBase is the parameter that represents the base address of the mapped section.
	FileViewBase = "view_base"
	// FileViewSize is the parameter that represents the size of the mapped section.
	FileViewSize = "view_size"
	// FileViewSectionType is the parameter that represents the mapped section type.
	FileViewSectionType = "section_type"

	// ModuleBase identifies the parameter name for the base address of the process in which the Mmdule is loaded.
	ModuleBase = "base_address"
	// ModuleSize represents the parameter name for the size of the module in bytes.
	ModuleSize = "module_size"
	// ModulePath is the parameter name that denotes the file path and extension of the DLL/executable Module.
	ModulePath = "file_path"
	// NetSize identifies the parameter name that represents the packet size.
	NetSize = "size"
	// NetDIP is the parameter name that denotes the destination IP address.
	NetDIP = "dip"
	// NetSIP is the parameter name that denotes the source IP address.
	NetSIP = "sip"
	// NetDport identifies the parameter name that represents destination port number.
	NetDport = "dport"
	// NetSport identifies the parameter name that represents source port number.
	NetSport = "sport"
	// NetMSS is the parameter name that represents the maximum TCP segment size.
	NetMSS = "mss"
	// NetRcvWin is the parameter name that represents TCP segment's receive window size.
	NetRcvWin = "rcvwin"
	// NetSAckopt is the parameter name that represents Selective Acknowledgment option in TCP header.
	NetSAckopt = "sack_opt"
	// NetTsopt is the parameter name that represents the time stamp option in TCP header.
	NetTsopt = "timestamp_opt"
	// NetWsopt is the parameter name that represents the window scale option in TCP header.
	NetWsopt = "window_scale_opt"
	// NetRcvWinScale is the parameter name that represents the TCP receive window scaling factor.
	NetRcvWinScale = "recv_winscale"
	// NetSendWinScale is the parameter name that represents the TCP send window scaling factor.
	NetSendWinScale = "send_winscale"
	// NetSeqNum is the parameter name that represents the TCP sequence number.
	NetSeqNum = "seqnum"
	// NetStartTime is the parameter name that represents the TCP start time.
	NetStartTime = "start_time"
	// NetEndTime is the parameter name that represents the TCP end time.
	NetEndTime = "end_time"
	// NetConnID is the parameter name that represents a unique connection identifier.
	NetConnID = "connid"
	// NetL4Proto is the parameter name that identifies the Layer 4 protocol name.
	NetL4Proto = "l4_proto"
	// NetDportName is the field that denotes the destination port name.
	NetDportName = "dport_name"
	// NetSportName is the field that denotes the source port name.
	NetSportName = "sport_name"
	// NetSIPNames is the field that denotes the source IP address names.
	NetSIPNames = "sip_names"
	// NetDIPNames is the field that denotes the destination IP address names.
	NetDIPNames = "dip_names"

	// DNSName is the field that represents the DNS query name
	DNSName = "name"
	// DNSRR is the field that represents the DNS record type
	DNSRR = "rr"
	// DNSOpts is the field that represents the DNS options
	DNSOpts = "options"
	// DNSRcode is the field that represents the DNS response code
	DNSRcode = "rcode"
	// DNSAnswers is the field that represents DNS response answers
	DNSAnswers = "answers"

	// MemBaseAddress identifies the parameter that denotes the allocation base address.
	MemBaseAddress = "base_address"
	// MemRegionSize identifies the parameter that represents the allocated region size.
	MemRegionSize = "region_size"
	// MemAllocType identifies the parameter that represents allocation flags.
	MemAllocType = "alloc_type"
	// MemProtect identifies the parameter that represents the memory protection for the range of pages.
	MemProtect = "protection"
	// MemProtectMask identifies the parameter that represents the memory protection in mask notation
	MemProtectMask = "protection_mask"
	// MemPageType identifies the parameter that represents the allocated region type.
	MemPageType = "page_type"

	// LinkSource identifies the parameter that represents the source symbolic link object or other kernel object
	LinkSource = "source"
	// LinkTarget identifies the parameter that represents the target symbolic link object or other kernel object
	LinkTarget = "target"
)

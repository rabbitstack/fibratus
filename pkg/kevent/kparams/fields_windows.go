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

package kparams

const (
	// NTStatus is the parameter that identifies the NTSTATUS value.
	NTStatus = "status"

	// ProcessID represents the process identifier.
	ProcessID = "pid"
	// ProcessObject field represents the address of the process object in the kernel.
	ProcessObject = "kproc"
	// ThreadID field represents the thread identifier.
	ThreadID = "tid"
	// ProcessParentID field represents the parent process identifier.
	ProcessParentID = "ppid"
	// ProcessRealParentID field presents the real parent process identifier.
	ProcessRealParentID = "real_ppid"
	// SessionID fields represents the session identifier.
	SessionID = "session_id"
	// UserSID field is the security identifier associated to the process token under which it is run.
	UserSID = "sid"
	// Username field represents the username under which the event was generated.
	Username = "username"
	// Domain field represents the domain under which the event was generated.
	Domain = "domain"
	// ProcessName field denotes the process image name.
	ProcessName = "name"
	// Exe field denotes the full path of the executable.
	Exe = "exe"
	// Cmdline field represents the process command line.
	Cmdline = "cmdline"
	// DTB field denotes the address of the process directory table.
	DTB = "directory_table_base"
	// ExitStatus is the field that represents the process exit status.
	ExitStatus = "exit_status"
	// StartTime field denotes the process start time.
	StartTime = "start_time"

	// DesiredAccess field denotes the access rights for different kernel objects such as processes or threads.
	DesiredAccess = "desired_access"

	// BasePrio field is the thread base priority assigned by the scheduler.
	BasePrio = "base_prio"
	// IOPrio represents the filed that indicates the thread I/O priority.
	IOPrio = "io_prio"
	// PagePrio field denotes page priority.
	PagePrio = "page_prio"
	// KstackBase field is the start address of the kernel space stack.
	KstackBase = "kstack"
	// KstackLimit field is the end address of the kernel space stack.
	KstackLimit = "kstack_limit"
	// UstackBase field is the start address of the user space stack.
	UstackBase = "ustack"
	// UstackLimit field is the end address of the user space stack.
	UstackLimit = "ustack_limit"
	// StartAddr field is the address of the thread main function.
	StartAddr = "entrypoint"

	// FileObject determines the field name for the file object pointer.
	FileObject = "file_object"
	// FileName represents the field that designates the absolute path of the file.
	FileName = "file_name"
	// FileCreateOptions is the field that represents the values passed in the CreateDispositions parameter to the NtCreateFile function.
	FileCreateOptions = "create_options"
	// FileOperation is the field that represents the values passed in the CreateOptions parameter to the NtCreateFile function.
	FileOperation = "create_disposition"
	// FileCreated represents the name for the file creation field.
	FileCreated = "created"
	// FileAccessed represents the name for the file access field.
	FileAccessed = "accessed"
	// FileModified represents the name for the file modification field.
	FileModified = "modified"
	// FileShareMask represents the field name for the share access mask.
	FileShareMask = "share_mask"
	// FileType represents the field name that indicates the file type.
	FileType = "type"
	// FileAttributes is the field that represents file attribute values.
	FileAttributes = "attributes"
	// FileIoSize is the filed that represents the number of bytes in file read/write operations.
	FileIoSize = "io_size"
	// FileOffset represents the file for the file offset in read/write operations.
	FileOffset = "offset"
	// FileInfoClass represents the file information class.
	FileInfoClass = "class"
	// FileKey represents the directory key identifier in EnumDirectory events.
	FileKey = "file_key"
	// FileDirectory represents the field for the directory name in EnumDirectory events.
	FileDirectory = "directory"
	// FileIrpPtr represents the I/O request packet id.
	FileIrpPtr = "irp"
	// FileExtraInfo is the parameter that represents extra information returned by the file system for the operation. For example for a read request, the actual number of bytes that were read.
	FileExtraInfo = "extra_info"

	// RegKeyHandle identifies the parameter name for the registry key handle.
	RegKeyHandle = "key_handle"
	// RegKeyName represents the parameter name for the fully qualified key name.
	RegKeyName = "key_name"
	// RegValue identifies the parameter name that contains the value
	RegValue = "value"
	// RegValueType identifies the parameter that represents registry value type e.g (DWORD, BINARY)
	RegValueType = "value_type"

	// ImageBase identifies the parameter name for the base address of the process in which the image is loaded.
	ImageBase = "base_address"
	// ImageSize represents the parameter name for the size of the image in bytes.
	ImageSize = "image_size"
	// ImageCheckSum is the parameter name for image checksum.
	ImageCheckSum = "checksum"
	// ImageDefaultBase is the parameter name that represents image's base address.
	ImageDefaultBase = "default_address"
	// ImageFilename is the parameter name that denotes file name and extension of the DLL/executable image.
	ImageFilename = "file_name"
	// ImageSignatureLevel is the parameter denoting the loaded module signature level
	ImageSignatureLevel = "signature_level"
	// ImageSignatureType is the parameter denoting the loaded module signature type
	ImageSignatureType = "signature_type"

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

	// HandleID identifies the parameter that specifies the handle identifier.
	HandleID = "handle_id"
	// HandleObject identifies the parameter that represents the kernel object to which handle is associated.
	HandleObject = "handle_object"
	// HandleObjectName identifies the parameter that represents the kernel object name.
	HandleObjectName = "handle_name"
	// HandleObjectTypeID identifies the parameter that represents the kernel object type identifier.
	HandleObjectTypeID = "type_id"
)

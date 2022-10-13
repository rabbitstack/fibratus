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

package kparams

const (
	uniqueProcessKey = "UniqueProcessKey"
	processID        = "ProcessId"
	parentID         = "ParentId"
	sessionID        = "SessionId"
	exitStatus       = "ExitStatus"
	dirTableBase     = "DirectoryTableBase"
	userSID          = "UserSID"
	imageFileName    = "ImageFileName"
	imageName        = "ImageName"
	imagePath        = "ImagePath"
	commandLine      = "CommandLine"

	tthreadID       = "TThreadId"
	issuingThreadID = "IssuingThreadId"
	ttid            = "TTID"

	targetThreatID = "TargetThreatId" // Threat? MS typo?

	pid             = "PID"
	targetProcessID = "TargetProcessId"

	desiredAccess = "DesiredAccess"

	basePriority   = "BasePriority"
	ioPriority     = "IoPriority"
	pagePriority   = "PagePriority"
	stackBase      = "StackBase"
	stackLimit     = "StackLimit"
	userStackBase  = "UserStackBase"
	userStackLimit = "UserStackLimit"
	win32StartAddr = "Win32StartAddr"

	fileObject        = "FileObject"
	fileName          = "FileName"
	openPath          = "OpenPath"
	fileCreateOptions = "CreateOptions"
	fileShareAccess   = "ShareAccess"
	fileOffset        = "Offset"
	fileIoSize        = "IoSize"
	fileInfoClass     = "InfoClass"
	fileKey           = "FileKey"
	fileExtraInfo     = "ExtraInfo"
	fileIrpPtr        = "IrpPtr"
	fileAttributes    = "FileAttributes"

	keyName        = "KeyName"
	keyHandle      = "KeyHandle"
	registryStatus = "Status"

	ntStatus   = "NtStatus"
	returnCode = "ReturnCode"

	imageBase        = "ImageBase"
	imageSize        = "ImageSize"
	imageChecksum    = "ImageCheckSum"
	imageDefaultBase = "DefaultBase"

	netDaddr = "daddr"
	netSaddr = "saddr"
	netDport = "dport"
	netSport = "sport"
	netSize  = "size"

	handleID         = "Handle"
	handleObject     = "Object"
	handleObjectName = "ObjectName"
	handleObjectType = "ObjectType"
)

// Canonicalize takes an original kernel event property name and normalizes it
// to canonical parameter name.
func Canonicalize(name string) string {
	switch name {
	case tthreadID, issuingThreadID, ttid, targetThreatID:
		return ThreadID
	case processID, pid, targetProcessID:
		return ProcessID
	case uniqueProcessKey:
		return ProcessObject
	case parentID:
		return ProcessParentID
	case sessionID:
		return SessionID
	case imageFileName:
		return ProcessName
	case imageName, imagePath:
		return ImageFilename
	case commandLine:
		return Comm
	case userSID:
		return UserSID
	case exitStatus:
		return ExitStatus
	case dirTableBase:
		return DTB
	case basePriority:
		return BasePrio
	case ioPriority:
		return IOPrio
	case pagePriority:
		return PagePrio
	case stackBase:
		return KstackBase
	case stackLimit:
		return KstackLimit
	case userStackBase:
		return UstackBase
	case userStackLimit:
		return UstackLimit
	case win32StartAddr:
		return ThreadEntrypoint
	case fileObject:
		return FileObject
	case fileName, openPath:
		return FileName
	case fileCreateOptions:
		return FileCreateOptions
	case fileShareAccess:
		return FileShareMask
	case fileOffset:
		return FileOffset
	case fileIoSize:
		return FileIoSize
	case fileInfoClass:
		return FileInfoClass
	case fileKey:
		return FileKey
	case fileExtraInfo:
		return FileExtraInfo
	case fileIrpPtr:
		return FileIrpPtr
	case keyName:
		return RegKeyName
	case keyHandle:
		return RegKeyHandle
	case imageBase:
		return ImageBase
	case imageDefaultBase:
		return ImageDefaultBase
	case imageSize:
		return ImageSize
	case imageChecksum:
		return ImageCheckSum
	case netDaddr:
		return NetDIP
	case netSaddr:
		return NetSIP
	case netDport:
		return NetDport
	case netSport:
		return NetSport
	case netSize:
		return NetSize
	case handleID:
		return HandleID
	case handleObject:
		return HandleObject
	case handleObjectName:
		return HandleObjectName
	case handleObjectType:
		return HandleObjectTypeID
	case registryStatus, ntStatus, returnCode:
		return NTStatus
	case desiredAccess:
		return DesiredAccess
	case fileAttributes:
		return FileAttributes
	default:
		return ""
	}
}

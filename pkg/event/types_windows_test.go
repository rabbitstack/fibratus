/*
 * Copyright 2019-2026 by Nedim Sabic Sabic
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

package event

import (
	"testing"

	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"golang.org/x/sys/windows"
)

func TestNewTypeFromEventRecord(t *testing.T) {
	tests := []struct {
		name     string
		provider windows.GUID
		id       uint16
		opcode   uint8
		want     Type
	}{
		// Registry
		{
			name:     "Registry/CreateKey",
			provider: RegistryEventGUID,
			opcode:   RegCreateKeyID,
			want:     RegCreateKey,
		},
		{
			name:     "Registry/OpenKey",
			provider: RegistryEventGUID,
			opcode:   RegOpenKeyID,
			want:     RegOpenKey,
		},
		{
			name:     "Registry/DeleteKey",
			provider: RegistryEventGUID,
			opcode:   RegDeleteKeyID,
			want:     RegDeleteKey,
		},
		{
			name:     "Registry/QueryKey",
			provider: RegistryEventGUID,
			opcode:   RegQueryKeyID,
			want:     RegQueryKey,
		},
		{
			name:     "Registry/SetValue",
			provider: RegistryEventGUID,
			opcode:   RegSetValueID,
			want:     RegSetValue,
		},
		{
			name:     "Registry/DeleteValue",
			provider: RegistryEventGUID,
			opcode:   RegDeleteValueID,
			want:     RegDeleteValue,
		},
		{
			name:     "Registry/QueryValue",
			provider: RegistryEventGUID,
			opcode:   RegQueryValueID,
			want:     RegQueryValue,
		},
		{
			name:     "Registry/CreateKCB",
			provider: RegistryEventGUID,
			opcode:   RegCreateKCBID,
			want:     RegCreateKCB,
		},
		{
			name:     "Registry/DeleteKCB",
			provider: RegistryEventGUID,
			opcode:   RegDeleteKCBID,
			want:     RegDeleteKCB,
		},
		{
			name:     "Registry/KCBRundown",
			provider: RegistryEventGUID,
			opcode:   RegKCBRundownID,
			want:     RegKCBRundown,
		},
		{
			name:     "Registry/CloseKey",
			provider: RegistryEventGUID,
			opcode:   RegCloseKeyID,
			want:     RegCloseKey,
		},

		// File
		{
			name:     "File/FileRundown",
			provider: FileEventGUID,
			opcode:   FileRundownID,
			want:     FileRundown,
		},
		{
			name:     "File/MapViewOfSection",
			provider: FileEventGUID,
			opcode:   MapViewOfSectionID,
			want:     MapViewOfSection,
		},
		{
			name:     "File/UnmapViewOfSection",
			provider: FileEventGUID,
			opcode:   UnmapViewOfSectionID,
			want:     UnmapViewOfSection,
		},
		{
			name:     "File/MapViewSectionRundown",
			provider: FileEventGUID,
			opcode:   MapViewSectionRundownID,
			want:     MapViewSectionRundown,
		},
		{
			name:     "File/CreateFile",
			provider: FileEventGUID,
			opcode:   CreateFileID,
			want:     CreateFile,
		},
		{
			name:     "File/ReleaseFile",
			provider: FileEventGUID,
			opcode:   ReleaseFileID,
			want:     ReleaseFile,
		},
		{
			name:     "File/CloseFile",
			provider: FileEventGUID,
			opcode:   CloseFileID,
			want:     CloseFile,
		},
		{
			name:     "File/ReadFile",
			provider: FileEventGUID,
			opcode:   ReadFileID,
			want:     ReadFile,
		},
		{
			name:     "File/WriteFile",
			provider: FileEventGUID,
			opcode:   WriteFileID,
			want:     WriteFile,
		},
		{
			name:     "File/SetFileInformation",
			provider: FileEventGUID,
			opcode:   SetFileInformationID,
			want:     SetFileInformation,
		},
		{
			name:     "File/DeleteFile",
			provider: FileEventGUID,
			opcode:   DeleteFileID,
			want:     DeleteFile,
		},
		{
			name:     "File/RenameFile",
			provider: FileEventGUID,
			opcode:   RenameFileID,
			want:     RenameFile,
		},
		{
			name:     "File/EnumDirectory",
			provider: FileEventGUID,
			opcode:   EnumDirectoryID,
			want:     EnumDirectory,
		},
		{
			name:     "File/FileOpEnd",
			provider: FileEventGUID,
			opcode:   FileOpEndID,
			want:     FileOpEnd,
		},

		// Audit API -- these use EventDescriptor.ID, not Opcode.
		{
			name:     "AuditAPI/OpenProcess",
			provider: AuditAPIEventGUID,
			id:       OpenProcessID,
			want:     OpenProcess,
		},
		{
			name:     "AuditAPI/OpenThread",
			provider: AuditAPIEventGUID,
			id:       OpenThreadID,
			want:     OpenThread,
		},
		{
			name:     "AuditAPI/SetThreadContext",
			provider: AuditAPIEventGUID,
			id:       SetThreadContextID,
			want:     SetThreadContext,
		},
		{
			name:     "AuditAPI/CreateSymbolicLinkObject",
			provider: AuditAPIEventGUID,
			id:       CreateSymbolicLinkObjectID,
			want:     CreateSymbolicLinkObject,
		},

		// Stack walk
		{
			name:     "StackWalk",
			provider: StackWalkEventGUID,
			want:     StackWalk,
		},

		// Memory
		{
			name:     "Memory/VirtualAlloc",
			provider: MemoryEventGUID,
			opcode:   VirtualAllocID,
			want:     VirtualAlloc,
		},
		{
			name:     "Memory/VirtualFree",
			provider: MemoryEventGUID,
			opcode:   VirtualFreeID,
			want:     VirtualFree,
		},

		// TCP
		{
			name:     "TCP/AcceptIPv4",
			provider: NetworkTCPEventGUID,
			opcode:   AcceptTCPv4ID,
			want:     Accept,
		},
		{
			name:     "TCP/AcceptIPv6",
			provider: NetworkTCPEventGUID,
			opcode:   AcceptTCPv6ID,
			want:     Accept,
		},
		{
			name:     "TCP/SendIPv4",
			provider: NetworkTCPEventGUID,
			opcode:   SendV4ID,
			want:     Send,
		},
		{
			name:     "TCP/SendIPv6",
			provider: NetworkTCPEventGUID,
			opcode:   SendV6ID,
			want:     Send,
		},
		{
			name:     "TCP/RecvIPv4",
			provider: NetworkTCPEventGUID,
			opcode:   RecvV4ID,
			want:     Recv,
		},
		{
			name:     "TCP/RecvIPv6",
			provider: NetworkTCPEventGUID,
			opcode:   RecvV6ID,
			want:     Recv,
		},
		{
			name:     "TCP/ConnectIPv4",
			provider: NetworkTCPEventGUID,
			opcode:   ConnectTCPv4ID,
			want:     Connect,
		},
		{
			name:     "TCP/ConnectIPv6",
			provider: NetworkTCPEventGUID,
			opcode:   ConnectTCPv6ID,
			want:     Connect,
		},
		{
			name:     "TCP/DisconnectIPv4",
			provider: NetworkTCPEventGUID,
			opcode:   DisconnectTCPv4ID,
			want:     Disconnect,
		},
		{
			name:     "TCP/DisconnectIPv6",
			provider: NetworkTCPEventGUID,
			opcode:   DisconnectTCPv6ID,
			want:     Disconnect,
		},
		{
			name:     "TCP/ReconnectIPv4",
			provider: NetworkTCPEventGUID,
			opcode:   ReconnectTCPv4ID,
			want:     Reconnect,
		},
		{
			name:     "TCP/ReconnectIPv6",
			provider: NetworkTCPEventGUID,
			opcode:   ReconnectTCPv6ID,
			want:     Reconnect,
		},
		{
			name:     "TCP/RetransmitIPv4",
			provider: NetworkTCPEventGUID,
			opcode:   RetransmitTCPv4ID,
			want:     Retransmit,
		},
		{
			name:     "TCP/RetransmitIPv6",
			provider: NetworkTCPEventGUID,
			opcode:   RetransmitTCPv6ID,
			want:     Retransmit,
		},

		// UDP
		{
			name:     "UDP/SendIPv4",
			provider: NetworkUDPEventGUID,
			opcode:   SendV4ID,
			want:     Send,
		},
		{
			name:     "UDP/SendIPv6",
			provider: NetworkUDPEventGUID,
			opcode:   SendV6ID,
			want:     Send,
		},
		{
			name:     "UDP/RecvIPv4",
			provider: NetworkUDPEventGUID,
			opcode:   RecvV4ID,
			want:     Recv,
		},
		{
			name:     "UDP/RecvIPv6",
			provider: NetworkUDPEventGUID,
			opcode:   RecvV6ID,
			want:     Recv,
		},

		// DNS -- uses EventDescriptor.ID.
		{
			name:     "DNS/Query",
			provider: DNSEventGUID,
			id:       QueryDNSID,
			want:     QueryDNS,
		},
		{
			name:     "DNS/Reply",
			provider: DNSEventGUID,
			id:       ReplyDNSID,
			want:     ReplyDNS,
		},

		// Process
		{
			name:     "Process/CreateProcess",
			provider: ProcessEventGUID,
			opcode:   CreateProcessID,
			want:     CreateProcess,
		},
		{
			name:     "Process/TerminateProcess",
			provider: ProcessEventGUID,
			opcode:   TerminateProcessID,
			want:     TerminateProcess,
		},
		{
			name:     "Process/ProcessRundown",
			provider: ProcessEventGUID,
			opcode:   ProcessRundownID,
			want:     ProcessRundown,
		},

		// Process kernel -- uses EventDescriptor.ID.
		{
			name:     "ProcessKernel/CreateProcessInternal",
			provider: ProcessKernelEventGUID,
			id:       CreateProcessInternalID,
			want:     CreateProcessInternal,
		},
		{
			name:     "ProcessKernel/ProcessRundownInternal",
			provider: ProcessKernelEventGUID,
			id:       ProcessRundownInternalID,
			want:     ProcessRundownInternal,
		},
		{
			name:     "ProcessKernel/LoadModuleInternal",
			provider: ProcessKernelEventGUID,
			id:       LoadModuleInternalID,
			want:     LoadModuleInternal,
		},

		// Module
		{
			name:     "Module/UnloadModule",
			provider: ModuleEventGUID,
			opcode:   UnloadModuleID,
			want:     UnloadModule,
		},
		{
			name:     "Module/ModuleRundown",
			provider: ModuleEventGUID,
			opcode:   ModuleRundownID,
			want:     ModuleRundown,
		},
		{
			name:     "Module/LoadModule",
			provider: ModuleEventGUID,
			opcode:   LoadModuleID,
			want:     LoadModule,
		},

		// Thread
		{
			name:     "Thread/CreateThread",
			provider: ThreadEventGUID,
			opcode:   CreateThreadID,
			want:     CreateThread,
		},
		{
			name:     "Thread/TerminateThread",
			provider: ThreadEventGUID,
			opcode:   TerminateThreadID,
			want:     TerminateThread,
		},
		{
			name:     "Thread/ThreadRundown",
			provider: ThreadEventGUID,
			opcode:   ThreadRundownID,
			want:     ThreadRundown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &etw.EventRecord{
				Header: etw.EventHeader{
					ProviderID: tt.provider,
					EventDescriptor: etw.EventDescriptor{
						ID:     tt.id,
						Opcode: tt.opcode,
					},
				},
			}

			got := NewTypeFromEventRecord(r)

			if got != tt.want {
				t.Fatalf("NewTypeFromEventRecord() = %v, want %v", got, tt.want)
			}
		})
	}
}

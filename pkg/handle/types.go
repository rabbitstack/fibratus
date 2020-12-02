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

package handle

const (
	// ALPCPort represents the ALPC (Advanced Local Procedure Call) object ports
	ALPCPort = "ALPC Port"
	// Directory designates directory objects. They exist only within the object manager scope and do not correspond to any directory on the disk.
	Directory       = "Directory"
	EtwRegistration = "EtwRegistration"
	EtwConsumer     = "EtwConsumer"
	Event           = "Event"
	// File designates file handles (e.g. pipe, device, mailslot)
	File                 = "File"
	Key                  = "Key"
	Job                  = "Job"
	WaitCompletionPacket = "WaitCompletionPacket"
	IRTimer              = "IRTimer"
	TpWorkerFactory      = "TpWorkerFactory"
	IoCompletion         = "IoCompletion"
	Thread               = "Thread"
	Semaphore            = "Semaphore"
	Section              = "Section"
	Mutant               = "Mutant"
	Desktop              = "Desktop"
	WindowStation        = "WindowStation"
	Token                = "Token"
	UserApcReserve       = "UserApcReserve"

	Process = "Process"
	Unknown = "Unknown"
)

// GetShortName returns the short name for the handle type.
func GetShortName(typ string) string {
	switch typ {
	case ALPCPort:
		return "alpc"
	case Directory:
		return "d"
	case EtwRegistration:
		return "etwr"
	case Event:
		return "e"
	case File:
		return "f"
	case Process:
		return "ps"
	case Section:
		return "sec"
	case Semaphore:
		return "sem"
	default:
		return Unknown
	}
}

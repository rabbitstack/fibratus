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
	// EtwRegistration represents the ETW registration object
	EtwRegistration = "EtwRegistration"
	// EtwConsumer represents the ETW consumer object
	EtwConsumer     = "EtwConsumer"
	// Event denotest the event object
	Event           = "Event"
	// File designates file handles (e.g. pipe, device, mailslot)
	File                 = "File"
	// Key represents the registry key object
	Key                  = "Key"
	// Job represents the job object
	Job                  = "Job"
	// WaitCompletionPacket is the wait completion packet object
	WaitCompletionPacket = "WaitCompletionPacket"
	// IRTimer is the IR timer object
	IRTimer              = "IRTimer"
	// TpWorkerFactory represents the thread pool worker factory object
	TpWorkerFactory      = "TpWorkerFactory"
	// IoCompletion represents the IO completion object
	IoCompletion         = "IoCompletion"
	// Thread is the thread object
	Thread               = "Thread"
	// Semaphore represents the semaphore object
	Semaphore            = "Semaphore"
	// Section represents the section object
	Section              = "Section"
	// Mutant represents the mutant object
	Mutant               = "Mutant"
	// Desktop represents the desktop object
	Desktop              = "Desktop"
	// WindowStation represents the window station object
	WindowStation        = "WindowStation"
	// Token represents the token object
	Token                = "Token"
	// UserApcReserve represents the user APC reserve object
	UserApcReserve       = "UserApcReserve"
	// Process represents the process object
	Process = "Process"
	// Unknown is the unknown handle object
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

//go:build windows

/*
 * Copyright 2021-2026 by Nedim Sabic Sabic
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

package etw

import (
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
)

// enableKernelFlags crafts the system logger event mask from the
// probe config state.
// System logger flags is a bitmask that indicates which kernel events
// are delivered to the consumer when system logger session is started.
// At minimum, process events are published to the trace session as they
// represent the foundation for building the state machine.
// Note these flags are relevant to system logger traces and initializing
// the EnableFlags field of the etw.EventTraceProperties structure for any
// non-system logger providers will result in an error.
func enableKernelFlags(config config.EventSourceConfig) etw.EventTraceFlags {
	var flags etw.EventTraceFlags

	flags |= etw.Process

	if config.EnableThreadEvents {
		flags |= etw.Thread
	}
	if config.EnableModuleEvents {
		flags |= etw.Module
	}
	if config.EnableNetEvents {
		flags |= etw.NetTCPIP
	}
	if config.EnableRegistryEvents {
		flags |= etw.Registry
	}
	if config.EnableFileIOEvents {
		flags |= etw.DiskFileIO | etw.FileIO | etw.FileIOInit
	}
	if config.EnableVAMapEvents {
		flags |= etw.VaMap
	}
	if config.EnableMemEvents {
		flags |= etw.VirtualAlloc
	}

	return flags
}

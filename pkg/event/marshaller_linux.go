//go:build linux

/*
 * Copyright 2026 by Nedim Sabic Sabic
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

var (
	// SerializeHandles indicates if handles are serialized as part of the process state
	SerializeHandles bool
	// SerializeThreads indicates if threads are serialized as part of the process state
	SerializeThreads bool
	// SerializeModules indicates if modules are serialized as part of the process state
	SerializeModules bool
	// SerializePE indicates if PE metadata are serialized as part of the process state
	SerializePE bool
	// SerializeEnvs indicates if the environment variables are serialized as part of the process state
	SerializeEnvs bool
)

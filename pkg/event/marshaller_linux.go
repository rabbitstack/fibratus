//go:build linux

/*
 * Copyright 2026 by Mostafa Moradian
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
	"encoding/json"
	"fmt"

	capver "github.com/rabbitstack/fibratus/pkg/cap/version"
)

// SerializeEnvs indicates if environment variables are serialized with process state.
var SerializeEnvs bool

func serializationOptions() serializationConfig {
	return serializationConfig{envs: SerializeEnvs}
}

// MarshalJSON serializes the event to JSON.
func (e *Event) MarshalJSON() []byte {
	type plainEvent Event
	b, err := json.Marshal((*plainEvent)(e))
	if err != nil {
		return []byte("{}")
	}
	return b
}

// UnmarshalRaw recovers an event from a capture buffer.
func (e *Event) UnmarshalRaw(_ []byte, _ capver.Version) error {
	return fmt.Errorf("event capture unmarshalling is not implemented on Linux")
}

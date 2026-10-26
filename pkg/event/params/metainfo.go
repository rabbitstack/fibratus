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

package params

// BaseParamInfo describes the static properties of the event parameter. The
// information is declared once per event type in the event table, and it is
// shared by all event instances of that type. Parameter instances only keep
// a pointer to their descriptor.
type BaseParamInfo struct {
	// Name represents the name of the parameter (e.g. pid, sport).
	Name string
	// Type is the logical type of the parameter. For example, the `sport` parameter
	// has the `Port` type although its value is stored as the unsigned integer.
	Type Type
	// Flags represents the bitmask flags that apply to the flags-typed parameters.
	Flags Flags
	// Enum represents the enumeration that applies to the enum-typed parameters.
	Enum Enumeration
}

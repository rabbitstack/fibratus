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

package eval

// Resolvers are the injected resolvers of the expensive values.
// The Linux evaluators don't have any yet.
type Resolvers struct{}

// DefaultResolvers returns the resolvers backed by the agent's stores.
func DefaultResolvers() *Resolvers { return &Resolvers{} }

// peOptions has no PE directories to select on Linux.
func peOptions(Fields, []Segment) uint32 { return 0 }

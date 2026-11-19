/*
 * Copyright 2020-2021 by Nedim Sabic Sabic
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

package types

// Visitor is the type definition for the function that is
// invoked on each ancestor visit walk.
type Visitor func(*PS)

// Walk visits all ancestors of the given process, starting from the
// direct parent, and invokes the visitor function on each of them. The
// walk stops if the chain of parents loops back to an already visited
// process. Process identifiers are reused, so a stale parent link can
// make such cycles possible.
func Walk(v Visitor, ps *PS) {
	if ps == nil {
		return
	}
	visited := map[*PS]struct{}{ps: {}}
	for cur := ps; cur.Parent != nil; cur = cur.Parent {
		if _, ok := visited[cur.Parent]; ok {
			return
		}
		visited[cur.Parent] = struct{}{}
		v(cur.Parent)
	}
}

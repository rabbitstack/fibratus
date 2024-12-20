/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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

package sets

import "strings"

// IntersectionStrings computes the intersection of two
// string slices. The boolean argument specifies if the
// string comparison is case-sensitive or not.
func IntersectionStrings(s1, s2 []string, ignoreCase bool) []string {
	inter := make([]string, 0)
	bucket := map[string]bool{}

	for _, i := range s1 {
		for _, j := range s2 {
			var eq bool
			if ignoreCase {
				eq = strings.EqualFold(i, j) && !bucket[i]
			} else {
				eq = i == j && !bucket[i]
			}
			if eq {
				inter = append(inter, i)
				bucket[i] = true
			}
		}
	}

	return inter
}

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

package pe

import "fmt"

// Sec contains section attributes. On Linux this is only used so
// shared filter foreach helpers can compile against pe.Sec.
type Sec struct {
	Name    string
	Size    uint32
	Entropy float64
	Md5     string
}

func (s Sec) String() string {
	return fmt.Sprintf("Name: %s, Size: %d, Entropy: %f, Md5: %s", s.Name, s.Size, s.Entropy, s.Md5)
}

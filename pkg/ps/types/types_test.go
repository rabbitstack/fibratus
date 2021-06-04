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

import (
	"github.com/magiconair/properties/assert"
	"testing"
)

func TestVisit(t *testing.T) {
	ps1 := &PS{
		Name: "cmd.exe",
	}
	ps2 := &PS{
		Name:   "powershell.exe",
		Parent: ps1,
	}
	ps3 := &PS{
		Name:   "winword.exe",
		Parent: ps2,
	}

	expected := []string{"powershell.exe", "cmd.exe"}
	parents := make([]string, 0)

	Visit(func(ps *PS) { parents = append(parents, ps.Name) }, ps3)

	assert.Equal(t, expected, parents)

	ps4 := &PS{
		Name:   "iexplorer.exe",
		Parent: ps3,
	}
	ps5 := &PS{
		Name:   "dropper.exe",
		Parent: ps4,
	}

	expected1 := []string{"iexplorer.exe", "winword.exe", "powershell.exe", "cmd.exe"}
	parents1 := make([]string, 0)

	Visit(func(ps *PS) { parents1 = append(parents1, ps.Name) }, ps5)

	assert.Equal(t, expected1, parents1)
}

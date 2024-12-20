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

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestIntersectionStrings(t *testing.T) {
	var tests = []struct {
		s1         []string
		s2         []string
		ignoreCase bool
		in         []string
	}{
		{
			[]string{"-k", "DcomLaunch", "-p", "-s", "LSM"}, []string{"DcomLaunch", "-s"}, true, []string{"DcomLaunch", "-s"},
		},
		{
			[]string{"-k", "DcomLaunch", "-p", "-s", "LSM"}, []string{"DComLaunch", "-s"}, false, []string{"-s"},
		},
		{
			[]string{"-k", "DcomLaunch", "-p", "-s", "LSM"}, []string{"LocalSystemNetworkRestricted"}, true, []string{},
		},
		{
			[]string{"LSM", "-s"}, []string{"-S", "lsm"}, true, []string{"LSM", "-s"},
		},
	}

	for _, tt := range tests {
		t.Run(strings.Join(tt.in, ","), func(t *testing.T) {
			assert.Equal(t, tt.in, IntersectionStrings(tt.s1, tt.s2, tt.ignoreCase))
		})
	}
}

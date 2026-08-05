//go:build linux

/*
 * Copyright 2026 Fibratus contributors
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

package ebpf

import "testing"

func TestCheckKernelVersion(t *testing.T) {
	tests := []struct {
		current string
		minimum string
		wantErr bool
	}{
		{current: "5.9.0", minimum: "5.9", wantErr: false},
		{current: "5.10.1", minimum: "5.9", wantErr: false},
		{current: "6.12.76-linuxkit", minimum: "5.9", wantErr: false},
		{current: "5.8.18", minimum: "5.9", wantErr: true},
		{current: "4.18.0-553.el8", minimum: "5.9", wantErr: true},
	}
	for _, tt := range tests {
		err := checkKernelVersion(tt.current, tt.minimum)
		if (err != nil) != tt.wantErr {
			t.Fatalf("checkKernelVersion(%q, %q) err=%v wantErr=%v", tt.current, tt.minimum, err, tt.wantErr)
		}
	}
}

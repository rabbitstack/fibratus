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
	"github.com/rabbitstack/fibratus/pkg/util/bootid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"os"
	"testing"
	"time"
)

func TestVisit(t *testing.T) {
	p1 := &PS{
		Name: "powershell.exe",
		Parent: &PS{
			Name: "cmd.exe",
		},
	}
	p2 := &PS{
		Name: "iexplorer.exe",
		Parent: &PS{
			Name: "winword.exe",
			Parent: &PS{
				Name: "powershell.exe",
				Parent: &PS{
					Name: "cmd.exe",
				},
			},
		},
	}

	var tests = []struct {
		proc *PS
		want []string
	}{
		{&PS{Name: "winword.exe", Parent: p1}, []string{"powershell.exe", "cmd.exe"}},
		{&PS{Name: "dropper.exe", Parent: p2}, []string{"iexplorer.exe", "winword.exe", "powershell.exe", "cmd.exe"}},
	}

	for _, tt := range tests {
		ancestors := make([]string, 0)
		Walk(func(ps *PS) { ancestors = append(ancestors, ps.Name) }, tt.proc)
		assert.Equal(t, ancestors, tt.want)
	}
}

func TestPSArgs(t *testing.T) {
	ps := New(
		233,
		4532,
		"spotify.exe",
		"C:\\Users\\admin\\AppData\\Roaming\\Spotify\\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler \"--metrics-dir=C:\\Users\\admin\\AppData\\Local\\Spotify\\User Data\" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify",
		"C:\\Users\\admin\\AppData\\Roaming\\Spotify\\Spotify.exe",
		&windows.SID{},
		1)
	require.Len(t, ps.Args, 11)
	require.Equal(t, "/prefetch:7", ps.Args[2])
}

func TestUUID(t *testing.T) {
	now := time.Now()
	// try to obtain the UUID on a system process
	// will fail to obtain the process handle and thus
	// the UUID is derived from boot ID, process id and
	// process star time
	ps1 := &PS{
		PID:       4,
		StartTime: now,
	}
	uuid := (bootid.Read() << 30) + uint64(4) | uint64(now.UnixNano())
	assert.Equal(t, uuid, ps1.UUID())

	// now use the variant with process start key obtained
	// from the process object
	ps2 := &PS{
		PID: uint32(os.Getpid()),
	}
	tsUUID := (bootid.Read() << 30) + uint64(os.Getpid()) | uint64(now.UnixNano())
	assert.True(t, ps2.UUID() > 0 && ps2.UUID() != tsUUID)
}

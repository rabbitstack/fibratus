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
	"os"
	"sync"
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/bootid"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
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

func TestIsSeclogonSvc(t *testing.T) {
	var tests = []struct {
		ps *PS
		ok bool
	}{
		{&PS{Name: "svchost.exe", Exe: `C:\WINDOWS\system32\svchost.exe`, Cmdline: `C:\WINDOWS\system32\svchost.exe -k netsvcs -p -s Appinfo`}, false},
		{&PS{Name: "svchost.exe", Exe: `C:\WINDOWS\system32\svchost.exe`, Cmdline: `C:\WINDOWS\system32\svchost.exe -k netsvcs -p -s seclogon`}, true},
	}

	for _, tt := range tests {
		t.Run(tt.ps.Cmdline, func(t *testing.T) {
			assert.Equal(t, tt.ok, tt.ps.IsSeclogonSvc())
		})
	}
}

func TestIsAppinfoSvc(t *testing.T) {
	var tests = []struct {
		ps *PS
		ok bool
	}{
		{&PS{Name: "svchost.exe", Exe: `C:\WINDOWS\system32\svchost.exe`, Cmdline: `C:\WINDOWS\system32\svchost.exe -k netsvcs -p -s Appinfo`}, true},
		{&PS{Name: "svchost.exe", Exe: `C:\WINDOWS\system32\svchost.exe`, Cmdline: `C:\WINDOWS\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS`}, false},
	}

	for _, tt := range tests {
		t.Run(tt.ps.Cmdline, func(t *testing.T) {
			assert.Equal(t, tt.ok, tt.ps.IsAppinfoSvc())
		})
	}
}

func TestFindModuleByVa(t *testing.T) {
	base := va.Address(0x1000)

	tests := []struct {
		name            string
		initialModules  []Module
		liveModules     []sys.ProcessModule
		addr            va.Address
		expectNil       bool
		expectName      string
		expectCachedAdd bool
	}{
		{
			name: "hit lower bound inclusive",
			initialModules: []Module{
				{
					Name:        "C:\\Windows\\System32\\ntdll.dll",
					BaseAddress: base,
					Size:        0x200,
				},
			},
			addr:       base,
			expectName: "C:\\Windows\\System32\\ntdll.dll",
		},
		{
			name: "hit upper bound exclusive",
			initialModules: []Module{
				{
					Name:        "C:\\Windows\\System32\\ntdll.dll",
					BaseAddress: base,
					Size:        0x200,
				},
			},
			addr:      base.Inc(0x200),
			expectNil: true,
		},
		{
			name: "address inside range",
			initialModules: []Module{
				{
					Name:        "C:\\Windows\\System32\\ntdll.dll",
					BaseAddress: base,
					Size:        0x200,
				},
				{
					Name:        "C:\\Windows\\System32\\kernel32.dll",
					BaseAddress: base.Inc(10),
					Size:        0x100,
				},
			},
			addr:       base.Inc(0x100),
			expectName: "C:\\Windows\\System32\\ntdll.dll",
		},
		{
			name: "miss cached but hit live modules",
			liveModules: []sys.ProcessModule{
				{
					ModuleInfo: windows.ModuleInfo{
						BaseOfDll:   0x2000,
						SizeOfImage: 0x300,
					},
					Name: "C:\\Windows\\System32\\ntdll.dll",
				},
			},
			addr:            va.Address(0x2100),
			expectName:      "C:\\Windows\\System32\\ntdll.dll",
			expectCachedAdd: true,
		},
		{
			name: "miss both cached and live",
			initialModules: []Module{
				{
					Name:        "C:\\Windows\\System32\\ntdll.dll",
					BaseAddress: base,
					Size:        0x200,
				},
			},
			liveModules: []sys.ProcessModule{
				{
					ModuleInfo: windows.ModuleInfo{
						BaseOfDll:   0x3000,
						SizeOfImage: 0x100,
					},
					Name: "C:\\Windows\\System32\\ntdll.dll",
				},
			},
			addr:      va.Address(0x9999),
			expectNil: true,
		},
		{
			name: "multiple modules choose correct one",
			initialModules: []Module{
				{
					Name:        "C:\\Windows\\System32\\ntdll.dll",
					BaseAddress: va.Address(0x1000),
					Size:        0x100,
				},
				{
					Name:        "C:\\Windows\\System32\\kernel32.dll",
					BaseAddress: va.Address(0x2000),
					Size:        0x200,
				},
			},
			addr:       va.Address(0x2100),
			expectName: "C:\\Windows\\System32\\kernel32.dll",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ps := &PS{
				PID:     1234,
				Modules: append([]Module{}, tt.initialModules...),
			}

			ps.onceMods = sync.Once{}

			queryLiveModules = func(_ uint32) []sys.ProcessModule {
				var mods []sys.ProcessModule
				for _, m := range tt.liveModules {
					mods = append(mods, sys.ProcessModule{
						ModuleInfo: windows.ModuleInfo{
							BaseOfDll:   m.BaseOfDll,
							SizeOfImage: m.SizeOfImage,
						},
						Name: m.Name,
					})
				}
				return mods
			}

			mod := ps.FindModuleByVa(tt.addr)

			if tt.expectNil {
				if mod != nil {
					t.Fatalf("expected nil, got %+v", mod)
				}
				return
			}

			if mod == nil {
				t.Fatalf("expected module %s, got nil", tt.expectName)
			}

			if mod.Name != tt.expectName {
				t.Fatalf("expected module %s, got %s", tt.expectName, mod.Name)
			}

			if tt.expectCachedAdd {
				found := false
				for _, m := range ps.Modules {
					if m.Name == tt.expectName {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("expected module to be cached")
				}
			}
		})
	}
}

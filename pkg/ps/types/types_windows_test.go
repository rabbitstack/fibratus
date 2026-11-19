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
	"strings"
	"sync"
	"testing"
	"time"

	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/bootid"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestThreadString(t *testing.T) {
	th := Thread{
		Tid:         1,
		UstackBase:  va.Address(0x1000),
		UstackLimit: va.Address(0x2000),
		KstackBase:  va.Address(0x3000),
		KstackLimit: va.Address(0x4000),
	}
	s := th.String()
	assert.True(t, strings.Contains(s, "Ustack limit: "+th.UstackLimit.String()))
	assert.True(t, strings.Contains(s, "Kstack limit: "+th.KstackLimit.String()))
}

func TestStringShortIncludesIntegrityLevel(t *testing.T) {
	parent := &PS{PID: 1, Name: "explorer.exe"}
	child := &PS{PID: 2, Name: "cmd.exe", TokenIntegrityLevel: "HIGH", Parent: parent}
	assert.True(t, strings.Contains(child.StringShort(), "Integrity level: HIGH"))
	parent.Parent = nil
	assert.True(t, strings.Contains(parent.StringShort(), "Integrity level:"))
}

func TestFallbackUUID(t *testing.T) {
	now := time.Now()
	base := uuid(7, 4, now)

	assert.NotEqual(t, uint64(0), base)
	// deterministic
	assert.Equal(t, base, uuid(7, 4, now))
	// every component contributes to the result, even when the
	// start time has bits set where the other components have them
	assert.NotEqual(t, base, uuid(8, 4, now))
	assert.NotEqual(t, base, uuid(7, 5, now))
	assert.NotEqual(t, base, uuid(7, 4, now.Add(time.Nanosecond)))
}

func TestUUIDConcurrentAndStable(t *testing.T) {
	// the system process can't be opened, so the fallback variant is used
	ps := &PS{PID: 4, StartTime: time.Now()}

	var wg sync.WaitGroup
	results := make([]uint64, 16)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = ps.UUID()
		}(i)
	}
	wg.Wait()

	for _, uuid := range results {
		assert.NotEqual(t, uint64(0), uuid)
		assert.Equal(t, results[0], uuid)
	}
}

func TestAssignUUID(t *testing.T) {
	src := &PS{PID: 4, StartTime: time.Now()}
	dst := &PS{PID: 4}

	// nothing to assign when the source UUID was never initialized
	dst.AssignUUID(src)
	assert.Equal(t, uint64(0), dst.uuid)

	uuid := src.UUID()
	dst.AssignUUID(src)
	assert.Equal(t, uuid, dst.UUID())
}

func TestUUIDFromSequenceNumber(t *testing.T) {
	// the sequence number reported by the process creation event
	// is used as is, without asking the OS for the process
	ps := &PS{PID: 0x7ffffff1, SeqNum: 0xc30d, StartTime: time.Now()}
	assert.False(t, ps.IsUUIDExact(), "the uuid is not initialized yet")

	uuid := ps.UUID()
	assert.Equal(t, seqUUID(bootid.Read(), 0xc30d), uuid)
	assert.True(t, ps.IsUUIDExact())

	// different sequence numbers yield different identifiers
	// for the same pid and start time
	other := &PS{PID: ps.PID, SeqNum: 0xc30e, StartTime: ps.StartTime}
	assert.NotEqual(t, uuid, other.UUID())

	// the fallback variant is not exact
	fb := &PS{PID: 0x7ffffff1, StartTime: time.Now()}
	fb.UUID()
	assert.False(t, fb.IsUUIDExact())
}

func TestParentUUID(t *testing.T) {
	assert.Zero(t, (&PS{}).ParentUUID())
	ps := &PS{ParentSeqNum: 0xc30b}
	assert.Equal(t, seqUUID(bootid.Read(), 0xc30b), ps.ParentUUID())
	// the parent UUID matches the one the parent derives for itself
	parent := &PS{SeqNum: 0xc30b}
	assert.Equal(t, parent.UUID(), ps.ParentUUID())
}

func TestAssignUUIDKeepsExactness(t *testing.T) {
	src := &PS{PID: 2343, SeqNum: 7}
	src.UUID()
	dst := &PS{PID: 2893}
	dst.AssignUUID(src)
	assert.Equal(t, src.UUID(), dst.UUID())
	assert.True(t, dst.IsUUIDExact())
}

func TestFindModuleReturnsCopies(t *testing.T) {
	ps := &PS{PID: 1}
	ps.AddModule(Module{Name: `C:\Windows\System32\a.dll`, BaseAddress: va.Address(0x1000), Size: 0x100})
	ps.AddModule(Module{Name: `C:\Windows\System32\b.dll`, BaseAddress: va.Address(0x2000), Size: 0x100})

	byName := ps.FindModule("a.dll")
	byAddr := ps.FindModuleByAddr(va.Address(0x1000))
	byVa := ps.FindModuleByVa(va.Address(0x1010))
	require.NotNil(t, byName)
	require.NotNil(t, byAddr)
	require.NotNil(t, byVa)

	// removing the module shifts the slice, but must not change what the callers hold
	ps.RemoveModule(va.Address(0x1000))
	require.Len(t, ps.Modules, 1)
	assert.Equal(t, `C:\Windows\System32\a.dll`, byName.Name)
	assert.Equal(t, `C:\Windows\System32\a.dll`, byAddr.Name)
	assert.Equal(t, `C:\Windows\System32\a.dll`, byVa.Name)
	assert.Equal(t, `C:\Windows\System32\b.dll`, ps.Modules[0].Name)

	// mutating the copy doesn't leak into the state
	byName.Name = "mutated"
	assert.Nil(t, ps.FindModule("mutated"))

	assert.Nil(t, ps.FindModuleByAddr(va.Address(0x1000)))
}

func TestAddModuleConcurrentIsDeduplicated(t *testing.T) {
	ps := &PS{PID: 1}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ps.AddModule(Module{Name: `C:\Windows\System32\a.dll`, BaseAddress: va.Address(0x1000)})
		}()
	}
	wg.Wait()

	assert.Len(t, ps.Modules, 1)
}

func TestFindModuleByVaConcurrentIsDeduplicated(t *testing.T) {
	old := queryLiveModules
	defer func() { queryLiveModules = old }()
	queryLiveModules = func(_ uint32) []sys.ProcessModule {
		return []sys.ProcessModule{{
			ModuleInfo: windows.ModuleInfo{BaseOfDll: 0x5000, SizeOfImage: 0x1000},
			Name:       `C:\Windows\System32\live.dll`,
		}}
	}

	ps := &PS{PID: 1}

	var wg sync.WaitGroup
	found := make([]*Module, 16)
	for i := range found {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			found[i] = ps.FindModuleByVa(va.Address(0x5100))
		}(i)
	}
	wg.Wait()

	for _, mod := range found {
		require.NotNil(t, mod)
		assert.Equal(t, `C:\Windows\System32\live.dll`, mod.Name)
	}
	// the live module has been cached exactly once
	assert.Len(t, ps.Modules, 1)
}

func TestHandlesAddRemove(t *testing.T) {
	ps := &PS{PID: 1}
	ps.AddHandle(htypes.Handle{Num: windows.Handle(1), Name: "a"})
	ps.AddHandle(htypes.Handle{Num: windows.Handle(2), Name: "b"})
	ps.AddHandle(htypes.Handle{Num: windows.Handle(3), Name: "c"})

	full := ps.Handles
	require.Len(t, full, 3)

	ps.RemoveHandle(windows.Handle(2))
	require.Len(t, ps.Handles, 2)
	assert.Equal(t, windows.Handle(1), ps.Handles[0].Num)
	assert.Equal(t, windows.Handle(3), ps.Handles[1].Num)
	// the vacated slot must not retain the removed handle
	assert.Equal(t, htypes.Handle{}, full[2])

	// removing a handle that doesn't exist is a no-op
	ps.RemoveHandle(windows.Handle(99))
	assert.Len(t, ps.Handles, 2)
}

func TestHandlesConcurrentAccess(t *testing.T) {
	ps := &PS{PID: 1}

	var wg sync.WaitGroup
	for i := 1; i <= 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ps.AddHandle(htypes.Handle{Num: windows.Handle(i)})
			ps.RemoveHandle(windows.Handle(i))
		}(i)
	}
	wg.Wait()

	assert.Len(t, ps.Handles, 0)
}

func TestMmaps(t *testing.T) {
	ps := &PS{PID: 1}
	ps.AddMmap(Mmap{BaseAddress: va.Address(0x1000), File: "a"})
	ps.AddMmap(Mmap{BaseAddress: va.Address(0x2000), File: "b"})
	ps.AddMmap(Mmap{BaseAddress: va.Address(0x3000), File: "c"})

	full := ps.Mmaps

	m := ps.FindMmap(va.Address(0x2000))
	require.NotNil(t, m)
	assert.Equal(t, "b", m.File)
	assert.Nil(t, ps.FindMmap(va.Address(0x9999)))

	ps.RemoveMmap(va.Address(0x2000))
	require.Len(t, ps.Mmaps, 2)
	// callers keep a stable view of what they found
	assert.Equal(t, "b", m.File)
	assert.Equal(t, Mmap{}, full[2])
	assert.Nil(t, ps.FindMmap(va.Address(0x2000)))

	ps.RemoveMmap(va.Address(0x2000))
	assert.Len(t, ps.Mmaps, 2)
}

func TestMmapsConcurrentAccess(t *testing.T) {
	ps := &PS{PID: 1}

	var wg sync.WaitGroup
	for i := 1; i <= 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			addr := va.Address(i * 0x1000)
			ps.AddMmap(Mmap{BaseAddress: addr})
			_ = ps.FindMmap(addr)
			ps.RemoveMmap(addr)
		}(i)
	}
	wg.Wait()

	assert.Len(t, ps.Mmaps, 0)
}

func TestModuleMutatorsReportChanges(t *testing.T) {
	ps := &PS{Name: "Spotify.exe", Exe: "Spotify.exe", Threads: make(map[uint32]Thread)}

	assert.True(t, ps.AddThread(Thread{Tid: 1}))
	assert.False(t, ps.AddThread(Thread{Tid: 1}))
	assert.True(t, ps.RemoveThread(1))
	assert.False(t, ps.RemoveThread(1))

	assert.True(t, ps.AddModule(Module{Name: `C:\Spotify\Spotify.exe`, BaseAddress: 0x1000}))
	assert.False(t, ps.AddModule(Module{Name: `C:\Spotify\Spotify.exe`, BaseAddress: 0x1000}))
	assert.Equal(t, `C:\Spotify\Spotify.exe`, ps.Exe)
	assert.True(t, ps.RemoveModule(0x1000))
	assert.False(t, ps.RemoveModule(0x1000))

	ps.AddMmap(Mmap{BaseAddress: 0x2000})
	assert.True(t, ps.RemoveMmap(0x2000))
	assert.False(t, ps.RemoveMmap(0x2000))
}

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
	puuid := uuid(bootid.Read(), 4, now)
	assert.Equal(t, puuid, ps1.UUID())

	// now use the variant with process start key obtained
	// from the process object
	ps2 := &PS{
		PID: uint32(os.Getpid()),
	}
	tsUUID := uuid(bootid.Read(), uint32(os.Getpid()), now)
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

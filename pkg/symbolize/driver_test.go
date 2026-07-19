/*
 * Copyright 2021-present by Nedim Sabic Sabic
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

package symbolize

import (
	"sync"
	"testing"

	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/va"
)

func makeStore(devs []sys.Driver) *driverStore {
	return &driverStore{
		devs:    devs,
		drivers: make(map[va.Address]*sys.Driver),
	}
}

// Real-ish kernel driver addresses
const (
	ntosBase va.Address = 0xFFFFF80000000000
	ntosSize            = 0x800000 // 8 MB

	halBase va.Address = 0xFFFFF80008000000
	halSize            = 0x100000 // 1 MB
)

func realDrivers() []sys.Driver {
	return []sys.Driver{
		{Path: `\SystemRoot\system32\ntoskrnl.exe`, Base: ntosBase.Uintptr(), Size: ntosSize},
		{Path: `\SystemRoot\system32\hal.dll`, Base: halBase.Uintptr(), Size: halSize},
	}
}

func TestResolveHitsFirstDriver(t *testing.T) {
	ds := makeStore(realDrivers())

	addr := ntosBase + 0x1000 // well inside ntoskrnl
	drv := ds.resolve(addr)

	if drv == nil {
		t.Fatal("expected driver, got nil")
	}
	if drv.Path != `\SystemRoot\system32\ntoskrnl.exe` {
		t.Errorf("wrong driver: %s", drv.Path)
	}
}

func TestResolveHitsSecondDriver(t *testing.T) {
	ds := makeStore(realDrivers())

	addr := halBase + 0x500
	drv := ds.resolve(addr)

	if drv == nil {
		t.Fatal("expected driver, got nil")
	}
	if drv.Path != `\SystemRoot\system32\hal.dll` {
		t.Errorf("wrong driver: %s", drv.Path)
	}
}

func TestResolveExactBaseAddress(t *testing.T) {
	ds := makeStore(realDrivers())
	drv := ds.resolve(ntosBase)
	if drv == nil {
		t.Fatal("base address itself must resolve")
	}
}

func TestResolveLastByteInRange(t *testing.T) {
	ds := makeStore(realDrivers())
	last := ntosBase + va.Address(ntosSize) - 1
	drv := ds.resolve(last)
	if drv == nil {
		t.Fatal("last byte inside range must resolve")
	}
}

func TestResolveOneBeyondEndReturnsNil(t *testing.T) {
	ds := makeStore(realDrivers())
	beyond := ntosBase + va.Address(ntosSize) // exclusive upper bound
	drv := ds.resolve(beyond)
	if drv != nil {
		t.Errorf("address beyond driver range should return nil, got %s", drv.Path)
	}
}

func TestResolveUnknownAddressReturnsNil(t *testing.T) {
	ds := makeStore(realDrivers())
	drv := ds.resolve(0x0000000000001234) // user-space address
	if drv != nil {
		t.Errorf("unknown address should return nil, got %s", drv.Path)
	}
}

func TestResolveCacheHit(t *testing.T) {
	ds := makeStore(realDrivers())
	addr := ntosBase + 0x4000

	first := ds.resolve(addr)
	if first == nil {
		t.Fatal("first resolve failed")
	}

	// wipe devs so a miss would return nil to prove the cache is used
	ds.mux.Lock()
	ds.devs = nil
	ds.mux.Unlock()

	second := ds.resolve(addr)
	if second == nil {
		t.Fatal("second resolve (cache hit) returned nil")
	}
	if first != second {
		t.Error("cache hit must return the same pointer")
	}
}

func TestResolveConcurrentReads(t *testing.T) {
	ds := makeStore(realDrivers())
	addr := ntosBase + 0x2000

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			drv := ds.resolve(addr)
			if drv == nil {
				t.Errorf("concurrent resolve returned nil")
			}
		}()
	}
	wg.Wait()
}

func TestAddDriverResolvesAfterAdd(t *testing.T) {
	ds := makeStore(nil) // start empty

	const base va.Address = 0xFFFFF90000000000
	const size uint64 = 0x200000
	const path = `\Driver\custom.sys`

	ds.addDriver(base, size, path)

	drv := ds.resolve(base + 0x100)
	if drv == nil {
		t.Fatal("newly added driver must resolve")
	}
	if drv.Path != path {
		t.Errorf("got path %s, want %s", drv.Path, path)
	}
}

func TestAddDriverDoesNotAffectOtherRanges(t *testing.T) {
	ds := makeStore(realDrivers())

	const newBase va.Address = 0xFFFFF90000000000
	ds.addDriver(newBase, 0x10000, `\Driver\extra.sys`)

	// original drivers still work
	if ds.resolve(ntosBase+0x500) == nil {
		t.Error("existing driver should still resolve after addDriver")
	}
	// Unrelated address still nil.
	if ds.resolve(0x1) != nil {
		t.Error("unrelated address should still return nil")
	}
}

func TestRemoveDriverNoLongerResolves(t *testing.T) {
	ds := makeStore(realDrivers())

	// confirm it resolves before removal.
	if ds.resolve(ntosBase+0x1000) == nil {
		t.Fatal("precondition: driver must resolve before removal")
	}

	ds.removeDriver(ntosBase, ntosSize)

	if ds.resolve(ntosBase+0x1000) != nil {
		t.Error("driver must not resolve after removal")
	}
}

func TestRemoveDriverClearsCache(t *testing.T) {
	ds := makeStore(realDrivers())
	addr := ntosBase + 0x3000

	// populate the cache
	ds.resolve(addr)

	ds.removeDriver(ntosBase, ntosSize)

	// cache entry must be gone; since devs no longer contains the driver,
	// this must return nil rather than the stale cached pointer.
	if ds.resolve(addr) != nil {
		t.Error("cache must be invalidated after removeDriver")
	}
}

func TestRemoveDriverLeavesOtherDriversIntact(t *testing.T) {
	ds := makeStore(realDrivers())
	ds.removeDriver(ntosBase, ntosSize)

	drv := ds.resolve(halBase + 0x100)
	if drv == nil {
		t.Fatal("hal driver should survive ntoskrnl removal")
	}
	if drv.Path != `\SystemRoot\system32\hal.dll` {
		t.Errorf("wrong driver after partial removal: %s", drv.Path)
	}
}

func TestRemoveDriverNonExistentBase_NoOp(t *testing.T) {
	ds := makeStore(realDrivers())
	before := len(ds.devs)

	ds.removeDriver(0xDEAD000000000000, 0x1000) // not in the store

	if len(ds.devs) != before {
		t.Errorf("devs length changed after removing non-existent driver: %d → %d", before, len(ds.devs))
	}
}

func TestAddRemoveRoundTrip(t *testing.T) {
	ds := makeStore(nil)

	const base va.Address = 0xFFFFF80010000000
	const size uint64 = 0x50000

	ds.addDriver(base, size, `\Driver\roundtrip.sys`)
	ds.resolve(base + 0x100) // fill cache

	ds.removeDriver(base, size)

	if ds.resolve(base+0x100) != nil {
		t.Error("driver must be gone after round-trip removal")
	}
}

func TestAddNewDriverSameBase(t *testing.T) {
	ds := makeStore(realDrivers())

	const base va.Address = 0xFFFFF80010000000
	const size uint64 = 0x50000

	ds.addDriver(base, size, `\Driver\fileinfo.sys`)
	if len(ds.devs) != 3 {
		t.Error("must be 3 drivers in the store")
	}

	ds.addDriver(base, size, `\Driver\FLTMGR.SYS.sys`)
	if len(ds.devs) != 3 {
		t.Error("must be 3 drivers in the store")
	}

	drv := ds.resolve(base)
	if drv.Path != `\Driver\FLTMGR.SYS.sys` {
		t.Error("unexpected driver resolved")
	}
}

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

	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/va"
)

type driverStore struct {
	devs []sys.Driver
	// drivers maps resolved kernel addresses to the driver objects
	drivers map[va.Address]*sys.Driver
	mux     sync.RWMutex
}

func initDriverStore() *driverStore {
	return &driverStore{
		devs:    sys.EnumDevices(),
		drivers: make(map[va.Address]*sys.Driver),
	}
}

// resolve maps a kernel return address to a driver.
// If the kernel address is already resolved, then
// then the driver object is recovered from the cache.
// Returns nil if no module contains the address.
func (d *driverStore) resolve(addr va.Address) *sys.Driver {
	// driver already cached?
	d.mux.RLock()
	dev, isCached := d.drivers[addr]
	d.mux.RUnlock()
	if isCached {
		return dev
	}

	d.mux.Lock()
	defer d.mux.Unlock()
	for i := range d.devs {
		dev := &d.devs[i]
		base := va.Address(dev.Base)
		if addr >= base && addr < base.Inc(uint64(dev.Size)) {
			d.drivers[addr] = dev
			return dev
		}
	}

	return nil
}

func (d *driverStore) addDriver(base va.Address, size uint64, path string) {
	d.mux.Lock()
	defer d.mux.Unlock()

	dev := sys.Driver{
		Path: path,
		Base: base.Uintptr(),
		Size: uint32(size),
	}
	d.devs = append(d.devs, dev)
}

func (d *driverStore) removeDriver(base va.Address, size uint64) {
	d.mux.Lock()
	defer d.mux.Unlock()

	for i, dev := range d.devs {
		if dev.Base == base.Uintptr() {
			d.devs = append(d.devs[:i], d.devs[i+1:]...)
			break
		}
	}

	for addr := range d.drivers {
		if addr >= base && addr < base.Inc(size) {
			delete(d.drivers, addr)
		}
	}
}

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

package fs

import (
	"github.com/rabbitstack/fibratus/pkg/sys"
	"path/filepath"
	"strings"
)

// DevPathResolver resolves driver module paths from driver names.
// Prior to loading/unloading the kernel driver, the file object
// associated to it is opened. This gives us the opportunity to record
// the full path of the driver module and use it to augment events
// with this extra parameter.
type DevPathResolver struct {
	paths map[string]string
}

// NewDevPathResolver returns a new instance of driver device path resolver
func NewDevPathResolver() DevPathResolver {
	return DevPathResolver{paths: make(map[string]string)}
}

// AddPath adds the driver module path to the state of opened/created driver files.
func (d *DevPathResolver) AddPath(filename string) {
	isDriver := strings.EqualFold(filepath.Ext(filename), ".sys")
	if isDriver {
		d.paths[strings.ToLower(filepath.Base(filename))] = filename
	}
}

// RemovePath removes driver path from the state.
func (d *DevPathResolver) RemovePath(driver string) {
	delete(d.paths, driver)
}

// GetPath returns the full path to the driver module file. This method
// first perform a lookup in the opened/created driver modules. If the module
// is not found, then we enumerate all drivers and try to find the matching
// driver module path.
func (d *DevPathResolver) GetPath(driver string) string {
	path, ok := d.paths[strings.ToLower(driver)]
	if ok {
		return path
	}
	drivers := sys.EnumDevices()
	for _, drv := range drivers {
		if strings.EqualFold(strings.ToLower(filepath.Base(drv.Filename)), driver) {
			return drv.Filename
		}
	}
	return ""
}

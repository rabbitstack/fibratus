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

package symbolize

import (
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"golang.org/x/sys/windows"
	"runtime"
)

// Resolver is a minimal interface all symbol resolvers have to satisfy.
type Resolver interface {
	// Initialize performs preparation tasks prior to
	// initiating the symbolization process. This method
	// receives an optional options bitmask that may control
	// the symbol handler initialization.
	Initialize(proc windows.Handle, opts uint32) error
	// GetModuleName retrieves the module name for the given
	// process handle and address.
	GetModuleName(proc windows.Handle, addr va.Address) string
	// GetSymbolNameAndOffset returns the symbol name and
	// its offset for the given process handle and address.
	GetSymbolNameAndOffset(proc windows.Handle, addr va.Address) (string, uint64)
	// LoadModule loads the symbol table.
	LoadModule(proc windows.Handle, module string, addr va.Address) error
	// UnloadModule unloads the symbol table.
	UnloadModule(proc windows.Handle, addr va.Address)
	// Cleanup disposes any allocated resources.
	Cleanup(proc windows.Handle)
}

// DebugHelpResolver is the symbol resolver that
// piggybacks on top of Debug Help API facilities
// to convert raw stack addresses to symbols.
type DebugHelpResolver struct {
	config *config.Config
}

func NewDebugHelpResolver(config *config.Config) *DebugHelpResolver {
	return &DebugHelpResolver{config: config}
}

func (r *DebugHelpResolver) Initialize(proc windows.Handle, opts uint32) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	sys.SymSetOptions(opts)
	if !sys.SymInitialize(proc, r.config.SymbolPathsUTF16(), true) {
		return windows.GetLastError()
	}
	return nil
}

func (r *DebugHelpResolver) GetModuleName(proc windows.Handle, addr va.Address) string {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return sys.GetSymModuleName(proc, addr.Uint64())
}

func (r *DebugHelpResolver) GetSymbolNameAndOffset(proc windows.Handle, addr va.Address) (string, uint64) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return sys.GetSymName(proc, addr.Uint64())
}

func (r *DebugHelpResolver) LoadModule(proc windows.Handle, module string, addr va.Address) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	m, err := windows.UTF16PtrFromString(module)
	if err != nil {
		return err
	}
	if sys.SymLoadModule(proc, 0, m, nil, addr.Uint64(), 0, 0, 0) == 0 {
		return windows.GetLastError()
	}
	return nil
}

func (r *DebugHelpResolver) UnloadModule(proc windows.Handle, addr va.Address) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	sys.SymUnloadModule(proc, addr.Uint64())
}

func (r *DebugHelpResolver) Cleanup(proc windows.Handle) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	sys.SymCleanup(proc)
}

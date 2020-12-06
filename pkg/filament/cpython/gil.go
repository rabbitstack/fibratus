/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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

package cpython

/*
#include "api.h"
*/
import "C"
import (
	"runtime"
	"sync/atomic"
)

// PyGILState is the type alias for the native Python GIL state
type PyGILState C.PyGILState_STATE

// GIL is responsible for interacting with the Python GIL. Goroutines are executed on
// multiple threads and the scheduler might decide to pause the goroutine on one thread
// and resume it later in a different thread. This would cause catastrophic effects if
// the Python interpreter finds out the GIL was acquired in one thread but released in a
// different one. We have to provide extra safety to avoid runtime crashes at the cost of
// sacrificing some performance since we'll always stick the goroutine to be scheduled on
// the same thread.
type GIL struct {
	locked uint32
	state  PyGILState
	tstate *C.PyThreadState
}

// NewGIL creates a new instance of the GIL manager.
func NewGIL() *GIL {
	return &GIL{}
}

// SaveThread releases the global interpreter lock (if it has been created and thread
// support is enabled) and reset the thread state to NULL, returning the
// previous thread state (which is not NULL).
func (g *GIL) SaveThread() {
	g.tstate = C.PyEval_SaveThread()
}

// RestoreThread acquire the global interpreter lock (if it has been created and thread
// support is enabled) and set the thread state to tstate, which must not be
// NULL. If the lock has been created, the current thread must not have
// acquired it, otherwise deadlock ensues.
func (g *GIL) RestoreThread() {
	C.PyEval_RestoreThread(g.tstate)
}

// Lock acquires the GIL lock by ensuring the current thread is ready to call Python C API.
func (g *GIL) Lock() {
	runtime.LockOSThread()
	atomic.StoreUint32(&g.locked, 1)
	g.state = PyGILState(C.PyGILState_Ensure())
}

// Unlock releases the lock on the GIL.
func (g *GIL) Unlock() {
	atomic.StoreUint32(&g.locked, 0)
	C.PyGILState_Release(C.PyGILState_STATE(g.state))
	runtime.UnlockOSThread()
}

// Locked indicates if the lock on the GIL was acquired.
func (g *GIL) Locked() bool {
	return atomic.LoadUint32(&g.locked) > 0
}

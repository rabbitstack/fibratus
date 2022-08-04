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

package atomic

import atom "sync/atomic"

// Bool provides an atomic boolean type.
type Bool struct{ u Uint32 }

// Uint32 provides an atomic uint32 type.
type Uint32 struct{ value uint32 }

func MakeBool(v bool) Bool   { return Bool{MakeUint32(btoi(v))} }
func NewBool(v bool) *Bool   { return &Bool{MakeUint32(btoi(v))} }
func (b *Bool) Load() bool   { return b.u.Load() == 1 }
func (b *Bool) Store(v bool) { b.u.Store(btoi(v)) }

func MakeUint32(v uint32) Uint32 { return Uint32{v} }
func NewUint32(v uint32) *Uint32 { return &Uint32{v} }
func (u *Uint32) Load() uint32   { return atom.LoadUint32(&u.value) }
func (u *Uint32) Store(v uint32) { atom.StoreUint32(&u.value, v) }

func btoi(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

// +build kcap

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

package kcap

var (
	errWriteMagic   = func(err error) error { return fmt.Errorf("couldn't write magic number: %v", err) }
	errWriteVersion = func(v string, err error) error { return fmt.Errorf("couldn't write %s kcap digit: %v", v, err) }
	errWriteSection = func(s section.Type, err error) error { return fmt.Errorf("couldn't write %s kcap section: %v", s, err) }

	handleWriteErrors     = expvar.NewInt("kcap.handle.write.errors")
	kevtWriteErrors       = expvar.NewInt("kcap.kevt.write.errors")
	flusherErrors         = expvar.NewMap("kcap.flusher.errors")
	overflowKevents       = expvar.NewInt("kcap.overflow.kevents")
	kstreamConsumerErrors = expvar.NewInt("kcap.kstream.consumer.errors")
)

const maxKevtSize = math.MaxUint32

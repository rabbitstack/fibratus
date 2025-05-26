//go:build cap
// +build cap

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

package cap

import (
	"expvar"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/cap/section"
	"math"
)

var (
	// ErrWriteMagic signals magic write errors
	ErrWriteMagic = func(err error) error { return fmt.Errorf("couldn't write magic number: %v", err) }
	// ErrWriteVersion signals version write errors
	ErrWriteVersion = func(v string, err error) error { return fmt.Errorf("couldn't write %s cap digit: %v", v, err) }
	// ErrWriteSection signals section write errors
	ErrWriteSection = func(s section.Type, err error) error { return fmt.Errorf("couldn't write %s cap section: %v", s, err) }

	handleWriteErrors = expvar.NewInt("cap.handle.write.errors")
	evtWriteErrors    = expvar.NewInt("cap.evt.write.errors")
	flusherErrors     = expvar.NewMap("cap.flusher.errors")
	overflowEvents    = expvar.NewInt("cap.overflow.events")
	eventSourceErrors = expvar.NewInt("cap.eventsource.errors")
)

const maxKevtSize = math.MaxUint32

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
	"errors"
	"expvar"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/cap/section"
)

var (
	// ErrCapMagicMismatch signals invalid capture binary format
	ErrCapMagicMismatch = errors.New("invalid capture file magic number")
	// ErrMajorVer signals incompatible cap version
	ErrMajorVer = func(maj, min byte) error {
		return fmt.Errorf("incompatible cap version format. Required version %d.%d but %d.%d found", major, minor, maj, min)
	}
	// ErrReadVersion is thrown when version digit errors occur
	ErrReadVersion = func(s string, err error) error { return fmt.Errorf("couldn't read %s version digit: %v", s, err) }
	// ErrReadSection is thrown when section read errors occur
	ErrReadSection = func(s section.Type, err error) error { return fmt.Errorf("couldn't read %s section: %v", s, err) }

	capReadEvents            = expvar.NewInt("cap.read.events")
	capReadBytes             = expvar.NewInt("cap.read.bytes")
	capEventUnmarshalErrors  = expvar.NewInt("cap.event.unmarshal.errors")
	capHandleUnmarshalErrors = expvar.NewInt("cap.reader.handle.unmarshal.errors")
	capDroppedByFilter       = expvar.NewInt("cap.reader.dropped.by.filter")
)

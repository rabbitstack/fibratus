//go:build kcap
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

import (
	"errors"
	"expvar"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/kcap/section"
)

var (
	errKcapMagicMismatch = errors.New("invalid kcap file magic number")
	errMajorVer          = errors.New("incompatible kcap version format. Please upgrade Fibratus to newer version")
	errReadVersion       = func(s string, err error) error { return fmt.Errorf("couldn't read %s version digit: %v", s, err) }
	errReadSection       = func(s section.Type, err error) error { return fmt.Errorf("couldn't read %s section: %v", s, err) }

	kcapReadKevents           = expvar.NewInt("kcap.read.kevents")
	kcapReadBytes             = expvar.NewInt("kcap.read.bytes")
	kcapKeventUnmarshalErrors = expvar.NewInt("kcap.kevent.unmarshal.errors")
	kcapHandleUnmarshalErrors = expvar.NewInt("kcap.reader.handle.unmarshal.errors")
	kcapDroppedByFilter       = expvar.NewInt("kcap.reader.dropped.by.filter")
)

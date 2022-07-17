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

package filter

import (
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/rabbitstack/fibratus/pkg/filter/ql"
	"strings"
)

// New creates a new filter with the specified filter expression. The consumers must ensure
// the expression is correctly parsed before executing the filter. This is achieved by calling the
// Compile` method after constructing the filter.
func New(expr string, config *config.Config) Filter {
	accessors := []accessor{
		// general event parameters
		newKevtAccessor(),
		// process state and parameters
		newPSAccessor(),
	}
	kconfig := config.Kstream

	if kconfig.EnableThreadKevents {
		accessors = append(accessors, newThreadAccessor())
	}
	if kconfig.EnableImageKevents {
		accessors = append(accessors, newImageAccessor())
	}
	if kconfig.EnableFileIOKevents {
		accessors = append(accessors, newFileAccessor())
	}
	if kconfig.EnableRegistryKevents {
		accessors = append(accessors, newRegistryAccessor())
	}
	if kconfig.EnableNetKevents {
		accessors = append(accessors, newNetworkAccessor())
	}
	if kconfig.EnableHandleKevents {
		accessors = append(accessors, newHandleAccessor())
	}
	if config.PE.Enabled {
		accessors = append(accessors, newPEAccessor())
	}

	return &filter{
		parser:    ql.NewParser(expr),
		accessors: accessors,
		fields:    make([]fields.Field, 0),
		bindings:  make([]*ql.PatternBindingLiteral, 0),
	}
}

// NewFromCLI builds and compiles a filter by joining all the command line arguments into the filter expression.
func NewFromCLI(args []string, config *config.Config) (Filter, error) {
	expr := strings.Join(args, " ")
	if expr == "" {
		return nil, nil
	}
	filter := New(expr, config)
	if err := filter.Compile(); err != nil {
		return nil, fmt.Errorf("bad filter: \n  %v", err)
	}
	return filter, nil
}

// NewFromCLIWithAllAccessors builds and compiles a filter with all field accessors enabled.
func NewFromCLIWithAllAccessors(args []string) (Filter, error) {
	expr := strings.Join(args, " ")
	if expr == "" {
		return nil, nil
	}
	filter := &filter{
		parser:    ql.NewParser(expr),
		accessors: getAccessors(),
		fields:    make([]fields.Field, 0),
		bindings:  make([]*ql.PatternBindingLiteral, 0),
	}
	if err := filter.Compile(); err != nil {
		return nil, fmt.Errorf("bad filter: \n  %v", err)
	}
	return filter, nil
}

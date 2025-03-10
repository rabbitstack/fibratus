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
	"github.com/rabbitstack/fibratus/pkg/ps"
	"strings"
)

type opts struct {
	psnap ps.Snapshotter
}

// Option defines the option supplied to the filter
type Option func(o *opts)

// WithPSnapshotter passes a process snapshotter reference to the filter.
func WithPSnapshotter(psnap ps.Snapshotter) Option {
	return func(o *opts) {
		o.psnap = psnap
	}
}

// New creates a new filter with the specified filter expression. The consumers must ensure
// the expression is correctly parsed before executing the filter. This is achieved by calling the
// `Compile` method after constructing the filter.
func New(expr string, config *config.Config, options ...Option) Filter {
	var opts opts
	for _, opt := range options {
		opt(&opts)
	}
	accessors := []Accessor{
		// general event parameters
		newKevtAccessor(),
		// process state and parameters
		newPSAccessor(opts.psnap),
		// PE metadata
		newPEAccessor(),
	}
	kconfig := config.Kstream
	fconfig := config.Filters

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
	if kconfig.EnableMemKevents {
		accessors = append(accessors, newMemAccessor())
	}
	if kconfig.EnableDNSEvents {
		accessors = append(accessors, newDNSAccessor())
	}

	var parser *ql.Parser
	if fconfig.HasMacros() {
		parser = ql.NewParserWithConfig(expr, fconfig)
	} else {
		parser = ql.NewParser(expr)
	}

	return &filter{
		parser:         parser,
		accessors:      accessors,
		fields:         make([]Field, 0),
		segments:       make([]fields.Segment, 0),
		stringFields:   make(map[fields.Field][]string),
		boundFields:    make([]*ql.BoundFieldLiteral, 0),
		seqBoundFields: make(map[int][]BoundField),
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
		return nil, fmt.Errorf("bad filter:\n%v", err)
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
		parser:         ql.NewParser(expr),
		accessors:      GetAccessors(),
		fields:         make([]Field, 0),
		segments:       make([]fields.Segment, 0),
		stringFields:   make(map[fields.Field][]string),
		boundFields:    make([]*ql.BoundFieldLiteral, 0),
		seqBoundFields: make(map[int][]BoundField),
	}
	if err := filter.Compile(); err != nil {
		return nil, fmt.Errorf("bad filter:\n %v", err)
	}
	return filter, nil
}

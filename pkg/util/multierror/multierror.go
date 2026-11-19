// Copyright (c) 2017 Uber Technologies, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package multierror

import (
	"strings"
)

var sep = ", "

// Wrap takes a slice of errors and returns a single error that encapsulates
// those underlying errors. If the slice is nil or empty it returns nil.
// If the slice only contains a single element, that error is returned directly.
// When more than one error is wrapped, the Error() string is a concatenation
// of the Error() values of all underlying errors.
func Wrap(errs ...error) error {
	return MultiError(errs).flatten()
}

// WrapWithSeparator same as Wrap but uses a custom separator when joining
// error messages.
func WrapWithSeparator(s string, errs ...error) error {
	sep = s
	return MultiError(errs).flatten()
}

// MultiError bundles several errors together into a single error.
type MultiError []error

// Add append a new error to the bundle.
func (errors *MultiError) Add(err error) {
	*errors = append(*errors, err)
}

// Wrap returns a single error that encapsulates those underlying errors.
// Takes an optional slice of errors that are merged with the one in the
// bundle.
func (errors MultiError) Wrap(errs ...error) error {
	s := append(errors, errs...)
	return Wrap(s...)
}

// flatten returns either: nil, the only error, or the multiError instance itself
// if there are 0, 1, or more errors in the slice respectively.
func (errors MultiError) flatten() error {
	switch len(errors) {
	case 0:
		return nil
	default:
		for _, err := range errors {
			if err != nil {
				return errors
			}
		}
		return nil
	}
}

// Error returns a string like "[e1, e2, ...]" where each eN is the Error() of
// each error in the slice.
func (errors MultiError) Error() string {
	parts := make([]string, 0)
	for _, err := range errors {
		if err == nil {
			continue
		}
		parts = append(parts, err.Error())
	}
	return strings.Join(parts, sep)
}

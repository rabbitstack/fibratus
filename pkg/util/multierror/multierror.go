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
	return multiError(errs).flatten()
}

// WrapWithSeparator same as Wrap but uses a custom separator when joining
// error messages.
func WrapWithSeparator(s string, errs ...error) error {
	sep = s
	return multiError(errs).flatten()
}

// multiError bundles several errors together into a single error.
type multiError []error

// flatten returns either: nil, the only error, or the multiError instance itself
// if there are 0, 1, or more errors in the slice respectively.
func (errors multiError) flatten() error {
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
func (errors multiError) Error() string {
	parts := make([]string, 0)
	for _, err := range errors {
		if err == nil {
			continue
		}
		parts = append(parts, err.Error())
	}
	return strings.Join(parts, sep)
}

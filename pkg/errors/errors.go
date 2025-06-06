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

package errors

import (
	"fmt"
)

var (
	// ErrFeatureUnsupported is thrown when a certain feature was not triggered via the build flag
	ErrFeatureUnsupported = func(s string) error {
		return fmt.Errorf("fibratus was compiled without %s support. Please compile with the '%s' build flag", s, s)
	}

	// ErrHTTPServerUnavailable signals that the HTTP server is not running on the specified transport
	ErrHTTPServerUnavailable = func(transport string, err error) error {
		return fmt.Errorf("fibratus API server up and running on %s? %v", transport, err)
	}
)

// ErrParamNotFound is the error is thrown when a parameter is not present in the list of parameters
type ErrParamNotFound struct {
	Name string
}

// Error returns the error message.
func (e ErrParamNotFound) Error() string {
	return "couldn't find '" + e.Name + "' in event parameters"
}

// IsParamNotFound returns true if the error is ErrParamNotFound.
func IsParamNotFound(err error) bool {
	switch err.(type) {
	case *ErrParamNotFound:
		return true
	default:
		return false
	}
}

/*
 * Copyright 2026 by Nedim Sabic Sabic
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

package eval

import (
	"errors"
	"io/fs"
	"os"
	"sync"

	errs "github.com/rabbitstack/fibratus/pkg/errors"
)

const (
	// maxAccessorErrorKeys is the upper bound on the number of distinct
	// keys the accessor errors expvar map can hold.
	maxAccessorErrorKeys = 128
	// otherAccessorErrors is the key all the errors that don't fit in
	// the map are counted under.
	otherAccessorErrors = "other"
)

var (
	accessorErrorKeysMu sync.Mutex
	accessorErrorKeys   = make(map[string]struct{})
)

// countAccessorError increments the counter for the error returned by the
// accessor. The expvar map is keyed by a normalized error message and holds
// at most maxAccessorErrorKeys distinct keys, so messages that embed file
// paths, parameter names or other unbounded values can't grow it without limit.
func countAccessorError(err error) {
	accessorErrors.Add(accessorErrorKey(err), 1)
}

// accessorErrorKey returns the expvar map key for the error.
func accessorErrorKey(err error) string {
	key := normalizeAccessorError(err)

	accessorErrorKeysMu.Lock()
	defer accessorErrorKeysMu.Unlock()

	if _, ok := accessorErrorKeys[key]; ok {
		return key
	}
	if len(accessorErrorKeys) >= maxAccessorErrorKeys {
		return otherAccessorErrors
	}
	accessorErrorKeys[key] = struct{}{}
	return key
}

// normalizeAccessorError strips the variable parts of well-known error
// types, such as the path of file system errors or the name of the
// missing parameter.
func normalizeAccessorError(err error) string {
	var (
		pnfPtr *errs.ErrParamNotFound
		pnf    errs.ErrParamNotFound
		perr   *fs.PathError
		lerr   *os.LinkError
	)
	switch {
	case errors.As(err, &pnfPtr), errors.As(err, &pnf):
		return "parameter not found"
	case errors.As(err, &perr):
		return perr.Op + ": " + perr.Err.Error()
	case errors.As(err, &lerr):
		return lerr.Op + ": " + lerr.Err.Error()
	}
	return err.Error()
}

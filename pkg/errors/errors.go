/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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
	"errors"
	"fmt"
)

var (
	// ErrTraceAccessDenied is returned when user doesn't have enough privileges to start kernel trace
	ErrTraceAccessDenied = errors.New("not enough privileges to start the kernel trace. Only users with administrative privileges or users in the Performance Log Users group can start kernel traces")
	// ErrTraceInvalidParameter signals invalid values for trace session
	ErrTraceInvalidParameter = errors.New("trace has invalid values")
	// ErrTraceBadLength signals an incorrect size for internal structure buffer
	ErrTraceBadLength = errors.New("incorrect size of internal structure buffer")
	// ErrCannotUpdateTrace signals that the session with the same GUID was running and couldn't be updated
	ErrCannotUpdateTrace = errors.New("couldn't update the running trace")
	// ErrTraceNoSysResources signals that the maximum number of logging sessions has been reached
	ErrTraceNoSysResources = errors.New("maximum number of logging sessions has been reached")
	// ErrTraceDiskFull signals that there is not enough space on disk for the log file. Should never happen for real-time loggers
	ErrTraceDiskFull = errors.New("not enough disk space for writing to log file")
	// ErrInvalidTrace signals invalid trace handle
	ErrInvalidTrace = errors.New("invalid kernel trace handle")
	// ErrStopTrace is bubbled when controller is not able to stop kernel trace session
	ErrStopTrace = errors.New("an error occurred while stopping kernel trace")
	// ErrRestartTrace signals an error that is thrown when currently running kernel trace cannot be restarted
	ErrRestartTrace = errors.New("couldn't restart an already running kernel trace")
	// ErrTraceAlreadyRunning identifies kernel trace already running errors
	ErrTraceAlreadyRunning = errors.New("kernel trace is already running")
	// ErrEventCallbackException signals that an exception has occurred in the event processing function
	ErrEventCallbackException = errors.New("an exception occurred in the event callback function")
	// ErrKsessionNotRunning is thrown when kernel session from which consumer is trying to collect events is not running
	ErrKsessionNotRunning = errors.New("kernel session from which you are trying to consume events in real time is not running")
	// ErrTraceCancelled is thrown when in-progress kernel event trace is cancelled
	ErrTraceCancelled = errors.New("kernel event trace has been cancelled")
	// ErrInsufficentBuffer raises when the buffer size for allocating event metadata is higher then regular buffer size
	ErrInsufficentBuffer = errors.New("insufficient buffer size to allocate event metadata")
	// ErrEventSchemaNotFound signals missing event schema
	ErrEventSchemaNotFound = errors.New("event schema not found")
	// ErrNeedsReallocateBuffer is signaled when an API function requires bigger buffer size
	ErrNeedsReallocateBuffer = errors.New("buffer size is too small")
	// ErrCancelUpstreamKevent represents the error that is returned to denote that event is not going to be passed to upstream components such as aggregator or outputs
	ErrCancelUpstreamKevent = errors.New("cancel bubbling up the kernel event to upstream components")

	// ErrFeatureUnsupported is thrown when a certain feature was not triggered via the build flag
	ErrFeatureUnsupported = func(s string) error {
		return fmt.Errorf("fibratus was compiled without %s support. Please compile with the '%s' build flag", s, s)
	}

	// ErrHTTPServerUnavailable signals that the HTTP server is not running on the specified transport
	ErrHTTPServerUnavailable = func(transport string, err error) error {
		return fmt.Errorf("fibratus API server up and running on %s? %v", transport, err)
	}
)

// ErrKparamNotFound is the error is thrown when a parameter is not present in the list of parameters
type ErrKparamNotFound struct {
	Name string
}

// Error returns the error message.
func (e ErrKparamNotFound) Error() string {
	return "couldn't find " + e.Name + " in event parameters"
}

// IsCancelUpstreamKevent determines if the error being passed if of `ErrCancelUpstreamKevent` type.
func IsCancelUpstreamKevent(err error) bool { return err == ErrCancelUpstreamKevent }

// IsKparamNotFound returns true if the error is KparamNotFound.
func IsKparamNotFound(err error) bool {
	switch err.(type) {
	case *ErrKparamNotFound:
		return true
	default:
		return false
	}
}

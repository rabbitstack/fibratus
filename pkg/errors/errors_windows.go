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
)

var (
	// ErrTraceAccessDenied is returned when user doesn't have enough privileges to start kernel trace
	ErrTraceAccessDenied = errors.New("not enough privileges to start the trace. Only users with administrative privileges or users in the Performance Log Users group can start kernel traces")
	// ErrTraceInvalidParameter signals invalid values for trace session
	ErrTraceInvalidParameter = errors.New("trace has invalid values")
	// ErrTraceBadLength signals an incorrect size for internal structure buffer
	ErrTraceBadLength = errors.New("incorrect size of internal structure buffer")
	// ErrTraceNoSysResources signals that the maximum number of logging sessions has been reached
	ErrTraceNoSysResources = errors.New("maximum number of logging sessions has been reached")
	// ErrTraceDiskFull signals that there is not enough space on disk for the log file. Should never happen for real-time loggers
	ErrTraceDiskFull = errors.New("not enough disk space for writing to log file")
	// ErrInvalidTrace signals invalid trace handle
	ErrInvalidTrace = errors.New("invalid trace handle")
	// ErrRestartTrace signals an error that is thrown when currently running kernel trace cannot be restarted
	ErrRestartTrace = errors.New("couldn't restart an already running trace")
	// ErrTraceAlreadyRunning identifies kernel trace already running errors
	ErrTraceAlreadyRunning = errors.New("trace is already running")
	// ErrEventCallbackException signals that an exception has occurred in the event processing function
	ErrEventCallbackException = errors.New("an exception occurred in the event callback function")
	// ErrKsessionNotRunning is thrown when kernel session from which consumer is trying to collect events is not running
	ErrKsessionNotRunning = errors.New("session from which you are trying to consume events in real time is not running")
	// ErrTraceCancelled is thrown when in-progress kernel event trace is cancelled
	ErrTraceCancelled = errors.New("event trace has been cancelled")
)

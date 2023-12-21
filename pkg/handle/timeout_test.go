//go:build windows
// +build windows

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

package handle

import (
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"testing"
)

func TestTimeout(t *testing.T) {
	pipe, err := createPipe(`\\.\pipe\fibratus-timeout`, true)
	require.NoError(t, err)
	objectName, err := GetHandleWithTimeout(windows.Handle(pipe), 150)
	require.NoError(t, err)
	require.Equal(t, "\\Device\\NamedPipe\\fibratus-timeout", objectName)
}

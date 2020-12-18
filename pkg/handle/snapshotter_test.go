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
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/stretchr/testify/require"
	"os"
	"strings"
	"testing"
	"time"
)

func TestInitSnapshot(t *testing.T) {
	ch := make(chan bool)
	time.AfterFunc(time.Second*40, func() {
		ch <- true
		t.Fatal("snapshot callback was not triggered")
	})
	snap := NewSnapshotter(&config.Config{InitHandleSnapshot: true}, func(total, known uint64) {
		ch <- true
	})
	require.NotNil(t, snap)
	<-ch
}

func TestFindHandles(t *testing.T) {
	snap := NewSnapshotter(&config.Config{InitHandleSnapshot: true}, nil)
	handles, err := snap.FindHandles(uint32(os.Getppid()))
	require.NoError(t, err)
	require.NotEmpty(t, handles)

	var hasProcessHandle bool
	for _, h := range handles {
		if h.Type == "Process" && strings.Contains(h.Name, "fibratus_pkg_handle.exe") {
			hasProcessHandle = true
		}
	}

	require.True(t, hasProcessHandle)
}

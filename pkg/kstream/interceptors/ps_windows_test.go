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

package interceptors

import (
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func TestPsInterceptorIntercept(t *testing.T) {
	psnap := new(ps.SnapshotterMock)
	psi := newPsInterceptor(psnap, nil)

	kpars := kevent.Kparams{
		kparams.Comm:            {Name: kparams.Comm, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\svchost.exe -k RPCSS"},
		kparams.ProcessID:       {Name: kparams.ProcessID, Type: kparams.HexInt32, Value: kparams.Hex("36c")},
		kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.HexInt32, Value: kparams.Hex("26c")},
	}

	kevt := &kevent.Kevent{
		Type:    ktypes.CreateProcess,
		Kparams: kpars,
	}
	_, _, err := psi.Intercept(kevt)
	require.NoError(t, err)

	require.True(t, kevt.Kparams.Contains(kparams.Exe))
	exe, _ := kevt.Kparams.GetString(kparams.Exe)
	assert.Equal(t, "C:\\Windows\\system32\\svchost.exe", exe)
	pid, _ := kpars.GetPid()
	assert.Equal(t, uint32(876), pid)
	ppid, _ := kpars.GetPpid()
	assert.Equal(t, uint32(620), ppid)

	kpars1 := kevent.Kparams{
		kparams.Comm:            {Name: kparams.Comm, Type: kparams.UnicodeString, Value: "C:\\Windows\\System32\\smss.exe"},
		kparams.ProcessID:       {Name: kparams.ProcessID, Type: kparams.HexInt32, Value: kparams.Hex("36c")},
		kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.HexInt32, Value: kparams.Hex("26c")},
	}

	kevt1 := &kevent.Kevent{
		Type:    ktypes.EnumProcess,
		Kparams: kpars1,
	}
	err = os.Setenv("SystemRoot", "C:\\Windows")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = psi.Intercept(kevt1)
	require.NoError(t, err)
	exe, _ = kpars1.GetString(kparams.Exe)
	assert.Equal(t, "C:\\Windows\\System32\\smss.exe", exe)

	tpid := fmt.Sprintf("%x", os.Getpid())

	kpars2 := kevent.Kparams{
		kparams.Comm:            {Name: kparams.Comm, Type: kparams.UnicodeString, Value: "\"C:\\Windows\\System32\\smss.exe\""},
		kparams.ProcessID:       {Name: kparams.ProcessID, Type: kparams.HexInt32, Value: kparams.Hex(tpid)},
		kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.HexInt32, Value: kparams.Hex("26c")},
	}

	kevt2 := &kevent.Kevent{
		Type:    ktypes.CreateProcess,
		Kparams: kpars2,
	}
	_, _, err = psi.Intercept(kevt2)
	require.NoError(t, err)

	require.True(t, kevt2.Kparams.Contains(kparams.StartTime))

	cmdline, _ := kevt2.Kparams.GetString(kparams.Comm)
	require.Equal(t, "C:\\Windows\\System32\\smss.exe", cmdline)

	kpars3 := kevent.Kparams{
		kparams.ProcessID:       {Name: kparams.ProcessID, Type: kparams.HexInt32, Value: kparams.Hex(tpid)},
		kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.HexInt32, Value: kparams.Hex("26c")},
		kparams.Comm:            {Name: kparams.Comm, Type: kparams.UnicodeString, Value: "csrss.exe"},
		kparams.ProcessName:     {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "csrss.exe"},
	}

	kevt3 := &kevent.Kevent{
		Type:    ktypes.CreateProcess,
		Kparams: kpars3,
	}

	_, _, err = psi.Intercept(kevt3)
	require.NoError(t, err)
	cmdline1, _ := kevt3.Kparams.GetString(kparams.Comm)
	require.Equal(t, "C:\\Windows\\System32\\csrss.exe", cmdline1)
}

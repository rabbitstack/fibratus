//go:build linux && ebpf_integration

/*
 * Copyright 2026 by Mostafa Moradian
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

package ebpf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPrerequisitesAreMet asserts the host satisfies the runtime contract
// instead of skipping when it does not. A runner that silently loses runtime
// BTF, or drops below the kernel floor, would otherwise report a green suite
// that never loaded a program. It runs the same gate Open does, so the arch
// check is covered too.
func TestPrerequisitesAreMet(t *testing.T) {
	report, err := checkRuntimeSupport()
	if report != nil {
		t.Logf("kernel=%s (ok=%v, floor=%s) btf=%s (ok=%v) ringbuf=%v ringbuf_helper=%v tracing=%v iter=%v",
			report.KernelRelease, report.KernelOK, MinKernelVersion,
			report.BTFPath, report.BTFOK,
			report.RingbufOK, report.RingbufHelper, report.TracingOK, report.IterOK)
	}
	require.NoError(t, err, "host does not meet the Linux eBPF runtime contract")
	require.NotNil(t, report)
	require.True(t, report.KernelOK)
	require.True(t, report.BTFOK)
	require.True(t, report.RingbufOK)
	require.True(t, report.TracingOK)
	require.True(t, report.IterOK)
}

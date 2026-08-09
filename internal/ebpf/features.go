//go:build linux

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
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"golang.org/x/sys/unix"
)

const (
	// MinKernelVersion is the hard policy floor for the Linux eBPF backend.
	// BPF task iterators require Linux 5.9. bpf_d_path is intentionally unused
	// because it only appears in 5.10+.
	MinKernelVersion = "5.9"

	kernelBTFPath = "/sys/kernel/btf/vmlinux"
)

// PrerequisiteReport captures runtime probe results for the Linux eBPF backend.
type PrerequisiteReport struct {
	KernelRelease string
	KernelOK      bool
	BTFPath       string
	BTFOK         bool
	RingbufOK     bool
	TracingOK     bool
	IterOK        bool
	RingbufHelper bool
	Errors        []string
}

// ProbePrerequisites verifies the hard runtime contract for the Linux eBPF backend.
// Missing features produce an error; there is no BTFHub or build-host BTF fallback.
func ProbePrerequisites() (*PrerequisiteReport, error) {
	report := &PrerequisiteReport{BTFPath: kernelBTFPath}

	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return nil, fmt.Errorf("reading kernel release: %w", err)
	}
	report.KernelRelease = unix.ByteSliceToString(uts.Release[:])

	if err := checkKernelVersion(report.KernelRelease, MinKernelVersion); err != nil {
		report.Errors = append(report.Errors, err.Error())
	} else {
		report.KernelOK = true
	}

	if st, err := os.Stat(kernelBTFPath); err != nil || st.IsDir() || st.Size() == 0 {
		report.Errors = append(report.Errors, fmt.Sprintf("usable kernel BTF required at %s", kernelBTFPath))
	} else {
		report.BTFOK = true
	}

	if err := features.HaveMapType(ebpf.RingBuf); err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("ring buffer maps unavailable: %v", err))
	} else {
		report.RingbufOK = true
	}

	if err := features.HaveProgramType(ebpf.TracePoint); err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("tracepoint programs unavailable: %v", err))
	}
	if err := features.HaveProgramType(ebpf.Tracing); err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("tracing programs unavailable: %v", err))
	} else {
		report.TracingOK = true
	}

	// Helper probes are program-type specific in cilium/ebpf. TracePoint covers the
	// hot-path helpers; Tracing covers the iterator program class.
	if err := features.HaveProgramHelper(ebpf.TracePoint, asm.FnGetCurrentTask); err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("bpf_get_current_task helper unavailable: %v", err))
	}
	if err := features.HaveProgramHelper(ebpf.TracePoint, asm.FnRingbufReserve); err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("ringbuf helpers unavailable: %v", err))
	} else {
		report.RingbufHelper = true
	}

	// iter/task attach still needs a loaded program; ProbePrerequisites only checks
	// the necessary Tracing + runtime BTF preconditions. AttachIter in the spike
	// (and later loader) is the conclusive probe.
	if report.TracingOK && report.BTFOK {
		report.IterOK = true
	} else {
		report.Errors = append(report.Errors, "iter/task requires tracing programs and runtime kernel BTF")
	}

	if len(report.Errors) > 0 {
		return report, errors.New(strings.Join(report.Errors, "; "))
	}
	return report, nil
}

func checkKernelVersion(current, minimum string) error {
	cur, err := parseKernelVersion(current)
	if err != nil {
		return fmt.Errorf("parsing kernel version %q: %w", current, err)
	}
	min, err := parseKernelVersion(minimum)
	if err != nil {
		return fmt.Errorf("parsing minimum kernel version %q: %w", minimum, err)
	}
	if compareKernelVersion(cur, min) < 0 {
		return fmt.Errorf("kernel %s is below required %s", current, minimum)
	}
	return nil
}

type kernelVersion struct {
	major int
	minor int
	patch int
}

func parseKernelVersion(v string) (kernelVersion, error) {
	v = strings.SplitN(v, "-", 2)[0]
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return kernelVersion{}, fmt.Errorf("invalid version %q", v)
	}
	var kv kernelVersion
	if _, err := fmt.Sscanf(parts[0], "%d", &kv.major); err != nil {
		return kernelVersion{}, err
	}
	if _, err := fmt.Sscanf(parts[1], "%d", &kv.minor); err != nil {
		return kernelVersion{}, err
	}
	if len(parts) > 2 {
		_, _ = fmt.Sscanf(parts[2], "%d", &kv.patch)
	}
	return kv, nil
}

func compareKernelVersion(a, b kernelVersion) int {
	if a.major != b.major {
		return a.major - b.major
	}
	if a.minor != b.minor {
		return a.minor - b.minor
	}
	return a.patch - b.patch
}

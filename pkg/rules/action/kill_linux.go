//go:build linux

/*
 * Copyright 2026 by Mostafa Moradian
 * https://www.fibratus.io
 * All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
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

package action

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// userHZ is the tick rate in which /proc/<pid>/stat expresses the process start
// time. The kernel derives that field from task->start_boottime through
// nsec_to_clock_t, so dividing the captured nanoseconds by the same tick length
// reproduces it exactly.
const userHZ = uint64(100)

const nsecPerTick = uint64(1_000_000_000) / userHZ

type processInstance struct {
	pid           uint32
	startBootTime uint64
}

type killer struct {
	open           func(pid uint32) (int, error)
	readStartTicks func(pid uint32) (uint64, error)
	signal         func(fd int, sig unix.Signal) error
	closeFD        func(fd int) error
}

var defaultKiller = killer{
	open:           openPidfd,
	readStartTicks: readProcStartTicks,
	signal:         sendSignal,
	closeFD:        unix.Close,
}

// Kill terminates each process referenced by the action context.
func Kill(ctx *config.ActionContext) error {
	return defaultKiller.kill(ctx)
}

func (k killer) kill(ctx *config.ActionContext) error {
	if ctx == nil {
		return nil
	}
	instances := processInstances(ctx)
	log.Infof("killing pids=%v", pids(instances))

	errs := make([]error, 0)
	for _, inst := range instances {
		if err := k.killInstance(inst); err != nil {
			errs = append(errs, err)
		}
	}
	return multierror.Wrap(errs...)
}

// killInstance signals the process only if it is still the instance the rule
// matched on. The pidfd pins the process identifier for as long as it is open,
// so the identifier cannot be recycled between the start time comparison and
// the delivery of the signal.
func (k killer) killInstance(inst processInstance) error {
	if inst.pid == 0 {
		return fmt.Errorf("refusing to kill pid 0")
	}
	if inst.startBootTime == 0 {
		return fmt.Errorf("refusing to kill pid %d: missing process start time", inst.pid)
	}

	fd, err := k.open(inst.pid)
	if err != nil {
		if isGone(err) {
			return nil
		}
		return fmt.Errorf("couldn't pin pid %d for termination: %v", inst.pid, err)
	}
	defer func() {
		_ = k.closeFD(fd)
	}()

	ticks, err := k.readStartTicks(inst.pid)
	if err != nil {
		if isGone(err) {
			return nil
		}
		return fmt.Errorf("couldn't revalidate pid %d: %v", inst.pid, err)
	}
	if ticks != inst.startBootTime/nsecPerTick {
		return fmt.Errorf("refusing to kill pid %d: process instance identity does not match captured start time", inst.pid)
	}

	if err := k.signal(fd, unix.SIGKILL); err != nil {
		if isGone(err) {
			return nil
		}
		return fmt.Errorf("failed to kill pid %d: %v", inst.pid, err)
	}
	return nil
}

// processInstances resolves the distinct process instances the rule matched on.
// Clone events already carry the child identity, so the event process
// identifier always designates the process the rule fired for.
func processInstances(ctx *config.ActionContext) []processInstance {
	seen := make(map[uint32]processInstance, len(ctx.Events))
	for _, e := range ctx.Events {
		if e == nil {
			continue
		}
		start := e.GetParamAsUint64(params.StartBootTime)
		if start == 0 && e.PS != nil {
			start = e.PS.StartBootTime
		}
		seen[e.PID] = processInstance{pid: e.PID, startBootTime: start}
	}
	instances := make([]processInstance, 0, len(seen))
	for _, inst := range seen {
		instances = append(instances, inst)
	}
	slices.SortFunc(instances, func(a, b processInstance) int {
		return int(a.pid) - int(b.pid)
	})
	return instances
}

func pids(instances []processInstance) []uint32 {
	p := make([]uint32, 0, len(instances))
	for _, inst := range instances {
		p = append(p, inst.pid)
	}
	return p
}

func openPidfd(pid uint32) (int, error) {
	if pid > (^uint32(0) >> 1) {
		return 0, fmt.Errorf("pid %d is out of range", pid)
	}
	return unix.PidfdOpen(int(pid), 0)
}

func sendSignal(fd int, sig unix.Signal) error {
	return unix.PidfdSendSignal(fd, sig, nil, 0)
}

func readProcStartTicks(pid uint32) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	return parseProcStatStartTicks(data)
}

// parseProcStatStartTicks extracts the starttime field from a /proc/<pid>/stat
// record. The comm field is parenthesized and may itself contain spaces and
// parentheses, so the field split starts after its final delimiter.
func parseProcStatStartTicks(stat []byte) (uint64, error) {
	i := bytes.LastIndexByte(stat, ')')
	if i < 0 {
		return 0, fmt.Errorf("malformed /proc stat: missing comm")
	}
	fields := bytes.Fields(stat[i+1:])
	// starttime is the 22nd field, which is index 19 once pid and comm are cut
	if len(fields) < 20 {
		return 0, fmt.Errorf("malformed /proc stat: too few fields")
	}
	ticks, err := strconv.ParseUint(string(fields[19]), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("malformed /proc stat starttime: %w", err)
	}
	return ticks, nil
}

func isGone(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH)
}

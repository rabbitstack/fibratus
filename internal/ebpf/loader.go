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
	"io"
	"os"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type loader struct {
	exec     *execveObjects
	exit     *exitObjects
	clone    *cloneObjects
	iter     *prociterObjects
	links    []link.Link
	iterLink *link.Iter
	once     sync.Once
}

func loadCollections() (*loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock: %w", err)
	}

	execSpec, err := loadExecve()
	if err != nil {
		return nil, fmt.Errorf("loading execve collection spec: %w", err)
	}
	exitSpec, err := loadExit()
	if err != nil {
		return nil, fmt.Errorf("loading exit collection spec: %w", err)
	}
	cloneSpec, err := loadClone()
	if err != nil {
		return nil, fmt.Errorf("loading clone collection spec: %w", err)
	}
	iterSpec, err := loadProciter()
	if err != nil {
		return nil, fmt.Errorf("loading prociter collection spec: %w", err)
	}

	var execObjs execveObjects
	if err := execSpec.LoadAndAssign(&execObjs, nil); err != nil {
		return nil, fmt.Errorf("loading execve objects: %w", err)
	}

	replacements := map[string]*ebpf.Map{
		eventsMapName:      execObjs.Events,
		dropCountMapName:   execObjs.DropCount,
		scratchMapName:     execObjs.Scratch,
		scratchHeapMapName: execObjs.ScratchHeap,
		enabledMapName:     execObjs.Enabled,
	}
	opts := &ebpf.CollectionOptions{MapReplacements: replacements}

	var exitObjs exitObjects
	if err := exitSpec.LoadAndAssign(&exitObjs, opts); err != nil {
		_ = execObjs.Close()
		return nil, fmt.Errorf("loading exit objects: %w", err)
	}

	var cloneObjs cloneObjects
	if err := cloneSpec.LoadAndAssign(&cloneObjs, opts); err != nil {
		_ = exitObjs.Close()
		_ = execObjs.Close()
		return nil, fmt.Errorf("loading clone objects: %w", err)
	}

	var iterObjs prociterObjects
	if err := iterSpec.LoadAndAssign(&iterObjs, opts); err != nil {
		_ = cloneObjs.Close()
		_ = exitObjs.Close()
		_ = execObjs.Close()
		return nil, fmt.Errorf("loading prociter objects: %w", err)
	}

	return &loader{
		exec:  &execObjs,
		exit:  &exitObjs,
		clone: &cloneObjs,
		iter:  &iterObjs,
	}, nil
}

func (l *loader) eventsMap() *ebpf.Map { return l.exec.Events }

func (l *loader) dropCount() uint64 {
	var key uint32
	var drop uint64
	if l.exec == nil || l.exec.DropCount == nil {
		return 0
	}
	_ = l.exec.DropCount.Lookup(&key, &drop)
	return drop
}

func (l *loader) setEnabledTypes(cfg *config.EventSourceConfig) error {
	if l.exec == nil || l.exec.Enabled == nil {
		return fmt.Errorf("missing enabled map")
	}
	for typ, on := range enabledTypes(cfg) {
		key := uint32(typ)
		var val uint8
		if on {
			val = 1
		}
		if err := l.exec.Enabled.Put(&key, &val); err != nil {
			return fmt.Errorf("enabling %s: %w", typ, err)
		}
	}
	return nil
}

func enabledTypes(cfg *config.EventSourceConfig) map[event.Type]bool {
	file := cfg == nil || cfg.EnableFileIOEvents
	netev := cfg == nil || cfg.EnableNetEvents
	mem := cfg == nil || cfg.EnableMemEvents
	return map[event.Type]bool{
		event.Execve:         true,
		event.Exit:           true,
		event.Clone:          true,
		event.Kill:           true,
		event.Ptrace:         true,
		event.Prctl:          true,
		event.Openat:         file,
		event.Unlink:         file,
		event.Rename:         file,
		event.Connect:        netev,
		event.Accept:         netev,
		event.Mmap:           mem,
		event.ProcessVMRead:  mem,
		event.ProcessVMWrite: mem,
	}
}

// syscallsGroup is the tracefs group hosting raw syscall tracepoints.
const syscallsGroup = "syscalls"

// attachPrograms attaches the live-capture programs: raw syscall tracepoints
// plus the scheduler tp_btf hooks. These feed the ring buffer continuously,
// in contrast to the one-shot iter/task snapshot program started by
// runTaskIterator. The caller starts the ring buffer reader first so no
// events are lost between attachment and consumption.
func (l *loader) attachPrograms() error {
	type tp struct {
		name     string
		prog     *ebpf.Program
		optional bool
	}
	tracepoints := []tp{
		{"sys_enter_execve", l.exec.HandleSysEnterExecve, false},
		{"sys_exit_execve", l.exec.HandleSysExitExecve, false},
		{"sys_enter_execveat", l.exec.HandleSysEnterExecveat, false},
		{"sys_exit_execveat", l.exec.HandleSysExitExecveat, false},
		{"sys_enter_clone", l.clone.HandleSysEnterClone, false},
		{"sys_exit_clone", l.clone.HandleSysExitClone, false},
		{"sys_enter_clone3", l.clone.HandleSysEnterClone3, false},
		{"sys_exit_clone3", l.clone.HandleSysExitClone3, false},
		// fork/vfork are legacy wrappers. libc uses clone/clone3, and some
		// kernels refuse a perf link on these syscall tracepoints.
		{"sys_enter_fork", l.clone.HandleSysEnterFork, true},
		{"sys_exit_fork", l.clone.HandleSysExitFork, true},
		{"sys_enter_vfork", l.clone.HandleSysEnterVfork, true},
		{"sys_exit_vfork", l.clone.HandleSysExitVfork, true},
	}
	for _, t := range tracepoints {
		if t.prog == nil {
			return fmt.Errorf("missing program for %s/%s", syscallsGroup, t.name)
		}
		lnk, err := link.Tracepoint(syscallsGroup, t.name, t.prog, nil)
		if err != nil {
			if t.optional && isAttachUnavailable(err) {
				log.Warnf("skipping optional %s/%s: %v", syscallsGroup, t.name, err)
				continue
			}
			return fmt.Errorf("attaching %s/%s: %w", syscallsGroup, t.name, err)
		}
		l.links = append(l.links, lnk)
	}

	// Successful clones and process exits are captured from scheduler
	// tracepoints. Clone syscall exit tracepoints fire in the parent, and
	// exit/exit_group never return, so their exit tracepoints never fire.
	tracing := []struct {
		name string
		prog *ebpf.Program
	}{
		{"sched_process_fork", l.clone.HandleSchedProcessFork},
		{"sched_process_exit", l.exit.HandleSchedProcessExit},
	}
	for _, t := range tracing {
		if t.prog == nil {
			return fmt.Errorf("missing %s program", t.name)
		}
		lnk, err := link.AttachTracing(link.TracingOptions{Program: t.prog})
		if err != nil {
			return fmt.Errorf("attaching %s: %w", t.name, err)
		}
		l.links = append(l.links, lnk)
	}
	return nil
}

func isAttachUnavailable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrPermission) || errors.Is(err, os.ErrNotExist) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "permission denied") || strings.Contains(msg, "no such file")
}

func (l *loader) runTaskIterator() error {
	if l.iter == nil || l.iter.DumpTask == nil {
		return fmt.Errorf("missing iter/task program")
	}
	it, err := link.AttachIter(link.IterOptions{Program: l.iter.DumpTask})
	if err != nil {
		return fmt.Errorf("attaching iter/task: %w", err)
	}
	l.iterLink = it
	file, err := it.Open()
	if err != nil {
		return fmt.Errorf("opening task iterator: %w", err)
	}
	_, _ = io.Copy(io.Discard, file)
	return file.Close()
}

func (l *loader) Close() error {
	var err error
	l.once.Do(func() {
		for _, lnk := range l.links {
			if lnk != nil {
				if e := lnk.Close(); e != nil {
					err = e
				}
			}
		}
		if l.iterLink != nil {
			if e := l.iterLink.Close(); e != nil {
				err = e
			}
		}
		// Replacement collections share maps owned by execve. Close only their
		// programs so the canonical maps are released once.
		if l.iter != nil {
			if e := l.iter.prociterPrograms.Close(); e != nil {
				err = e
			}
		}
		if l.exit != nil {
			if e := l.exit.exitPrograms.Close(); e != nil {
				err = e
			}
		}
		if l.clone != nil {
			if e := l.clone.clonePrograms.Close(); e != nil {
				err = e
			}
		}
		if l.exec != nil {
			if e := l.exec.Close(); e != nil {
				err = e
			}
		}
		log.Debug("eBPF loader closed")
	})
	return err
}

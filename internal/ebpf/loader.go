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
		eventsMapName:    execObjs.Events,
		dropCountMapName: execObjs.DropCount,
		scratchMapName:   execObjs.Scratch,
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

func (l *loader) attachHotPath() error {
	type tp struct {
		group    string
		name     string
		prog     *ebpf.Program
		optional bool
	}
	tracepoints := []tp{
		{"syscalls", "sys_enter_execve", l.exec.HandleSysEnterExecve, false},
		{"syscalls", "sys_exit_execve", l.exec.HandleSysExitExecve, false},
		{"syscalls", "sys_enter_execveat", l.exec.HandleSysEnterExecveat, false},
		{"syscalls", "sys_exit_execveat", l.exec.HandleSysExitExecveat, false},
		{"syscalls", "sys_exit_exit_group", l.exit.HandleSysExitExitGroup, false},
		{"syscalls", "sys_exit_exit", l.exit.HandleSysExitExit, false},
		{"syscalls", "sys_enter_clone", l.clone.HandleSysEnterClone, false},
		{"syscalls", "sys_exit_clone", l.clone.HandleSysExitClone, false},
		{"syscalls", "sys_enter_clone3", l.clone.HandleSysEnterClone3, false},
		{"syscalls", "sys_exit_clone3", l.clone.HandleSysExitClone3, false},
		// fork/vfork are legacy wrappers. libc uses clone/clone3, and some
		// kernels refuse a perf link on these syscall tracepoints.
		{"syscalls", "sys_enter_fork", l.clone.HandleSysEnterFork, true},
		{"syscalls", "sys_exit_fork", l.clone.HandleSysExitFork, true},
		{"syscalls", "sys_enter_vfork", l.clone.HandleSysEnterVfork, true},
		{"syscalls", "sys_exit_vfork", l.clone.HandleSysExitVfork, true},
	}
	for _, t := range tracepoints {
		if t.prog == nil {
			return fmt.Errorf("missing program for %s/%s", t.group, t.name)
		}
		lnk, err := link.Tracepoint(t.group, t.name, t.prog, nil)
		if err != nil {
			if t.optional && isAttachUnavailable(err) {
				log.Warnf("skipping optional %s/%s: %v", t.group, t.name, err)
				continue
			}
			return fmt.Errorf("attaching %s/%s: %w", t.group, t.name, err)
		}
		l.links = append(l.links, lnk)
	}

	if l.clone.HandleSchedProcessFork == nil {
		return fmt.Errorf("missing sched_process_fork program")
	}
	fork, err := link.AttachTracing(link.TracingOptions{Program: l.clone.HandleSchedProcessFork})
	if err != nil {
		return fmt.Errorf("attaching sched_process_fork: %w", err)
	}
	l.links = append(l.links, fork)
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

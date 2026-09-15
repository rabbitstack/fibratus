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
	file     *fileObjects
	net      *netObjects
	mem      *memObjects
	ctl      *ctlObjects
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
	fileSpec, err := loadFile()
	if err != nil {
		return nil, fmt.Errorf("loading file collection spec: %w", err)
	}
	netSpec, err := loadNet()
	if err != nil {
		return nil, fmt.Errorf("loading net collection spec: %w", err)
	}
	memSpec, err := loadMem()
	if err != nil {
		return nil, fmt.Errorf("loading mem collection spec: %w", err)
	}
	ctlSpec, err := loadCtl()
	if err != nil {
		return nil, fmt.Errorf("loading ctl collection spec: %w", err)
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

	var fileObjs fileObjects
	if err := fileSpec.LoadAndAssign(&fileObjs, opts); err != nil {
		_ = iterObjs.Close()
		_ = cloneObjs.Close()
		_ = exitObjs.Close()
		_ = execObjs.Close()
		return nil, fmt.Errorf("loading file objects: %w", err)
	}

	var netObjs netObjects
	if err := netSpec.LoadAndAssign(&netObjs, opts); err != nil {
		_ = fileObjs.Close()
		_ = iterObjs.Close()
		_ = cloneObjs.Close()
		_ = exitObjs.Close()
		_ = execObjs.Close()
		return nil, fmt.Errorf("loading net objects: %w", err)
	}

	var memObjs memObjects
	if err := memSpec.LoadAndAssign(&memObjs, opts); err != nil {
		_ = netObjs.Close()
		_ = fileObjs.Close()
		_ = iterObjs.Close()
		_ = cloneObjs.Close()
		_ = exitObjs.Close()
		_ = execObjs.Close()
		return nil, fmt.Errorf("loading mem objects: %w", err)
	}

	var ctlObjs ctlObjects
	if err := ctlSpec.LoadAndAssign(&ctlObjs, opts); err != nil {
		_ = memObjs.Close()
		_ = netObjs.Close()
		_ = fileObjs.Close()
		_ = iterObjs.Close()
		_ = cloneObjs.Close()
		_ = exitObjs.Close()
		_ = execObjs.Close()
		return nil, fmt.Errorf("loading ctl objects: %w", err)
	}

	return &loader{
		exec:  &execObjs,
		exit:  &exitObjs,
		clone: &cloneObjs,
		iter:  &iterObjs,
		file:  &fileObjs,
		net:   &netObjs,
		mem:   &memObjs,
		ctl:   &ctlObjs,
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
func (l *loader) attachPrograms(cfg *config.EventSourceConfig) error {
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
		{"sys_enter_kill", l.ctl.HandleSysEnterKill, false},
		{"sys_exit_kill", l.ctl.HandleSysExitKill, false},
		// tkill is an obsolescent predecessor of tgkill; treat it like the
		// other legacy syscall tracepoints.
		{"sys_enter_tkill", l.ctl.HandleSysEnterTkill, true},
		{"sys_exit_tkill", l.ctl.HandleSysExitTkill, true},
		{"sys_enter_tgkill", l.ctl.HandleSysEnterTgkill, false},
		{"sys_exit_tgkill", l.ctl.HandleSysExitTgkill, false},
		{"sys_enter_ptrace", l.ctl.HandleSysEnterPtrace, false},
		{"sys_exit_ptrace", l.ctl.HandleSysExitPtrace, false},
		{"sys_enter_prctl", l.ctl.HandleSysEnterPrctl, false},
		{"sys_exit_prctl", l.ctl.HandleSysExitPrctl, false},
	}
	if cfg == nil || cfg.EnableFileIOEvents {
		// Legacy variants (open, unlink, rename) follow the fork/vfork
		// precedent: some kernels refuse perf links on them.
		tracepoints = append(tracepoints,
			tp{"sys_enter_open", l.file.HandleSysEnterOpen, true},
			tp{"sys_exit_open", l.file.HandleSysExitOpen, true},
			tp{"sys_enter_openat", l.file.HandleSysEnterOpenat, false},
			tp{"sys_exit_openat", l.file.HandleSysExitOpenat, false},
			tp{"sys_enter_openat2", l.file.HandleSysEnterOpenat2, false},
			tp{"sys_exit_openat2", l.file.HandleSysExitOpenat2, false},
			tp{"sys_enter_unlink", l.file.HandleSysEnterUnlink, true},
			tp{"sys_exit_unlink", l.file.HandleSysExitUnlink, true},
			tp{"sys_enter_unlinkat", l.file.HandleSysEnterUnlinkat, false},
			tp{"sys_exit_unlinkat", l.file.HandleSysExitUnlinkat, false},
			tp{"sys_enter_rename", l.file.HandleSysEnterRename, true},
			tp{"sys_exit_rename", l.file.HandleSysExitRename, true},
			tp{"sys_enter_renameat", l.file.HandleSysEnterRenameat, false},
			tp{"sys_exit_renameat", l.file.HandleSysExitRenameat, false},
			tp{"sys_enter_renameat2", l.file.HandleSysEnterRenameat2, false},
			tp{"sys_exit_renameat2", l.file.HandleSysExitRenameat2, false},
		)
	}
	if cfg == nil || cfg.EnableNetEvents {
		tracepoints = append(tracepoints,
			tp{"sys_enter_connect", l.net.HandleSysEnterConnect, false},
			tp{"sys_exit_connect", l.net.HandleSysExitConnect, false},
			tp{"sys_enter_accept", l.net.HandleSysEnterAccept, false},
			tp{"sys_exit_accept", l.net.HandleSysExitAccept, false},
			tp{"sys_enter_accept4", l.net.HandleSysEnterAccept4, false},
			tp{"sys_exit_accept4", l.net.HandleSysExitAccept4, false},
		)
	}
	if cfg == nil || cfg.EnableMemEvents {
		tracepoints = append(tracepoints,
			tp{"sys_enter_mmap", l.mem.HandleSysEnterMmap, false},
			tp{"sys_exit_mmap", l.mem.HandleSysExitMmap, false},
			tp{"sys_enter_process_vm_readv", l.mem.HandleSysEnterProcessVmReadv, false},
			tp{"sys_exit_process_vm_readv", l.mem.HandleSysExitProcessVmReadv, false},
			tp{"sys_enter_process_vm_writev", l.mem.HandleSysEnterProcessVmWritev, false},
			tp{"sys_exit_process_vm_writev", l.mem.HandleSysExitProcessVmWritev, false},
		)
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
		if l.ctl != nil {
			if e := l.ctl.ctlPrograms.Close(); e != nil {
				err = e
			}
		}
		if l.mem != nil {
			if e := l.mem.memPrograms.Close(); e != nil {
				err = e
			}
		}
		if l.net != nil {
			if e := l.net.netPrograms.Close(); e != nil {
				err = e
			}
		}
		if l.file != nil {
			if e := l.file.filePrograms.Close(); e != nil {
				err = e
			}
		}
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

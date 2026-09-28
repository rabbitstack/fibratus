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
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/rabbitstack/fibratus/internal/ebpf/bpf"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/filter"
)

func (l *loader) populateApprovers(plan *filter.ApproverPlan) error {
	if l == nil || l.exec == nil {
		return fmt.Errorf("approver maps are not loaded")
	}
	if plan == nil {
		plan = filter.AllowAllPlan()
	}

	cur, err := l.approverGen()
	if err != nil {
		return err
	}
	inactive := uint32(1) - cur
	if err := l.clearGeneration(inactive); err != nil {
		return fmt.Errorf("clearing inactive approver generation: %w", err)
	}
	if err := l.writePlan(inactive, plan); err != nil {
		return err
	}
	// The retired generation is left populated on purpose. A program that read
	// the old generation before the flip still resolves its lookups against it;
	// wiping it here would turn those in-flight events into drops. The next
	// reload clears it before reusing it.
	if err := l.exec.ApproverGen.Put(uint32(0), inactive); err != nil {
		return fmt.Errorf("flipping approver generation: %w", err)
	}
	return nil
}

func (l *loader) approverGen() (uint32, error) {
	var key, gen uint32
	if err := l.exec.ApproverGen.Lookup(&key, &gen); err != nil {
		return 0, fmt.Errorf("reading approver generation: %w", err)
	}
	return gen & 1, nil
}

func (l *loader) approverRejects() uint64 {
	var key uint32
	var n uint64
	if l.exec == nil || l.exec.ApproverReject == nil {
		return 0
	}
	_ = l.exec.ApproverReject.Lookup(&key, &n)
	return n
}

func (l *loader) writePlan(gen uint32, plan *filter.ApproverPlan) error {
	for i := uint32(0); i < approverTypeMax; i++ {
		key := gen*approverTypeMax + i
		typ := event.Type(i)
		pol := plan.Policy(typ)
		mode := policyMode(pol, typ)
		if err := l.exec.ApproverMode.Put(&key, &mode); err != nil {
			return fmt.Errorf("writing approver mode for type %d: %w", i, err)
		}
		if mode == 0 {
			continue
		}
		if err := l.writePolicy(gen, typ, pol); err != nil {
			return err
		}
	}
	return nil
}

func policyMode(pol filter.TypePolicy, typ event.Type) uint8 {
	if filter.AlwaysAllowed(typ) || pol.DefaultAllow {
		return 0
	}
	var mode uint8
	if pol.RequirePID {
		mode |= approverReqPID
	}
	if pol.RequireFilename {
		mode |= approverReqFile
	}
	// The kernel only parses a destination port out of the stashed sockaddr for
	// connect. Enforcing a port on any other type would compare against zero and
	// drop everything, so those types keep the rest of their policy instead.
	if pol.RequirePort && typ == event.Connect {
		mode |= approverReqPort
	}
	return mode
}

func (l *loader) writePolicy(gen uint32, typ event.Type, pol filter.TypePolicy) error {
	id := uint32(typ)
	present := uint8(1)
	if pol.RequirePID {
		for _, pid := range pol.PIDs {
			key := bpf.ExecveApproverPidKey{Gen: gen, Type: id, Pid: pid}
			if err := l.exec.ApproverPid.Put(&key, &present); err != nil {
				return fmt.Errorf("writing pid approver: %w", err)
			}
		}
	}
	if pol.RequirePort && typ == event.Connect {
		for _, port := range pol.Ports {
			key := bpf.ExecveApproverPortKey{Gen: gen, Type: id, Port: port}
			if err := l.exec.ApproverPort.Put(&key, &present); err != nil {
				return fmt.Errorf("writing port approver: %w", err)
			}
		}
	}
	if pol.RequireFilename {
		for _, path := range pol.FileExact {
			key := bpf.ExecveApproverFileKey{Gen: gen, Type: id}
			copy(key.Path[:], path)
			if err := l.exec.ApproverFileEq.Put(&key, &present); err != nil {
				return fmt.Errorf("writing file approver: %w", err)
			}
		}
		pre := l.prefixMap(gen)
		if pre == nil {
			return fmt.Errorf("missing filename prefix map for generation %d", gen)
		}
		for _, prefix := range pol.FilePrefix {
			if prefix == "" || len(prefix) > len(bpf.ExecveApproverLpmKey{}.Path) {
				continue
			}
			key := bpf.ExecveApproverLpmKey{Prefixlen: uint32(len(prefix) * 8)}
			copy(key.Path[:], prefix)
			if err := pre.Put(&key, &present); err != nil {
				return fmt.Errorf("writing file prefix approver: %w", err)
			}
		}
	}
	return nil
}

func (l *loader) prefixMap(gen uint32) *ebpf.Map {
	if gen == 0 {
		return l.exec.ApproverFilePre0
	}
	return l.exec.ApproverFilePre1
}

func (l *loader) clearGeneration(gen uint32) error {
	if err := deleteHashGen(l.exec.ApproverPid, gen, func(k bpf.ExecveApproverPidKey) uint32 { return k.Gen }); err != nil {
		return err
	}
	if err := deleteHashGen(l.exec.ApproverPort, gen, func(k bpf.ExecveApproverPortKey) uint32 { return k.Gen }); err != nil {
		return err
	}
	if err := deleteHashGen(l.exec.ApproverFileEq, gen, func(k bpf.ExecveApproverFileKey) uint32 { return k.Gen }); err != nil {
		return err
	}
	if err := deleteAll(l.prefixMap(gen)); err != nil {
		return err
	}
	for i := uint32(0); i < approverTypeMax; i++ {
		key := gen*approverTypeMax + i
		var mode uint8
		if err := l.exec.ApproverMode.Put(&key, &mode); err != nil {
			return err
		}
	}
	return nil
}

func deleteHashGen[K any](m *ebpf.Map, gen uint32, genOf func(K) uint32) error {
	if m == nil {
		return fmt.Errorf("missing approver map")
	}
	var key K
	var val uint8
	stale := make([]K, 0)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		if genOf(key) == gen {
			stale = append(stale, key)
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for i := range stale {
		if err := m.Delete(&stale[i]); err != nil {
			return err
		}
	}
	return nil
}

func deleteAll(m *ebpf.Map) error {
	if m == nil {
		return fmt.Errorf("missing approver map")
	}
	var key bpf.ExecveApproverLpmKey
	var val uint8
	stale := make([]bpf.ExecveApproverLpmKey, 0)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		stale = append(stale, key)
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for i := range stale {
		if err := m.Delete(&stale[i]); err != nil {
			return err
		}
	}
	return nil
}

func sharedMaps(exec *bpf.ExecveObjects) map[string]*ebpf.Map {
	return map[string]*ebpf.Map{
		eventsMapName:         exec.Events,
		dropCountMapName:      exec.DropCount,
		scratchMapName:        exec.Scratch,
		scratchHeapMapName:    exec.ScratchHeap,
		enabledMapName:        exec.Enabled,
		approverGenMapName:    exec.ApproverGen,
		approverModeMapName:   exec.ApproverMode,
		approverPIDMapName:    exec.ApproverPid,
		approverPortMapName:   exec.ApproverPort,
		approverFileEqMapName: exec.ApproverFileEq,
		approverFilePre0Name:  exec.ApproverFilePre0,
		approverFilePre1Name:  exec.ApproverFilePre1,
		approverFileHeapName:  exec.ApproverFileHeap,
		approverLPMHeapName:   exec.ApproverLpmHeap,
		approverRejectMapName: exec.ApproverReject,
	}
}

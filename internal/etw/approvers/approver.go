/*
 * Copyright 2020-present by Nedim Sabic Sabic
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

package approvers

import (
	"path/filepath"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/filter/ql"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"github.com/rabbitstack/fibratus/pkg/util/wildcard"
)

// Approver represents the contract that every approver must satisfy.
type Approver interface {
	// Approve receives a raw event recored. It may return
	// a new event record, and always returns a flag to
	// indicate if the event is approved or rejected.
	Approve(r *etw.EventRecord) (*etw.EventRecord, bool)
}

// Approvers is the registry for all known approvers.
type Approvers struct {
	approvers []Approver

	fs *fs
}

// New creates a new approvers set.
func New(psnap ps.Snapshotter, r *config.RulesCompileResult) Approvers {
	p := Approvers{
		approvers: make([]Approver, 0),
	}

	p.fs = newFSApprover(r).(*fs)

	p.approvers = append(p.approvers, p.fs)
	if r != nil {
		p.approvers = append(p.approvers, newRegistryApprover(r))
	}
	if r != nil {
		p.approvers = append(p.approvers, newProcApprover(psnap, r))
	}

	return p
}

// Approve renders a verdict about the event record.
// It evalutes available approvers against the event
// and if it satisifes the main condition for rule
// assertion, this method returns true. Otherwise, it
// returns false and instructs the consumer to drop the
// event record.
func (p *Approvers) Approve(r *etw.EventRecord) (*etw.EventRecord, bool) {
	if len(p.approvers) == 0 {
		return r, true
	}

	rec := r
	for _, approver := range p.approvers {
		e, ok := approver.Approve(rec)
		if !ok {
			return rec, false
		}
		rec = e
	}

	return rec, true
}

// Cleanup housekeeps approvers state.
func (p *Approvers) Cleanup(r *etw.EventRecord) {
	p.fs.cleanup(r)
}

// approver contains the base logic any approver can consume.
type approver struct {
	r *config.RulesCompileResult
}

func (p *approver) approvePath(path string) bool {
	return p.matchPredicate(p.r.Approvers.Paths, path)
}

func (p *approver) approveBasename(path string) bool {
	return p.matchPredicate(p.r.Approvers.Bases, filepath.Base(path))
}

func (p *approver) approveExtension(path string) bool {
	return p.matchPredicate(p.r.Approvers.Extensions, filepath.Ext(path))
}

func (p *approver) approveKey(key string) bool {
	return p.matchPredicate(p.r.Approvers.Keys, key)
}

func (p *approver) approveExecutable(exe string) bool {
	return p.matchPredicate(p.r.Approvers.Executables, exe)
}

func (*approver) matchPredicate(m map[string][]string, v string) bool {
	for op, patterns := range m {
		for _, pattern := range patterns {
			switch op {
			case ql.IMatches.String():
				if wildcard.Match(pattern, v, false) {
					return true
				}
			case ql.IContains.String():
				if strings.Contains(strings.ToLower(v), pattern) {
					return true
				}
			case ql.Eq.String(), ql.In.String():
				return v == pattern
			case ql.IEq.String(), ql.IIn.String():
				return strings.EqualFold(v, pattern)
			case ql.IStartswith.String():
				return strings.HasPrefix(strings.ToLower(v), pattern)
			case ql.IEndswith.String():
				return strings.HasSuffix(strings.ToLower(v), pattern)
			}
		}
	}
	return false
}

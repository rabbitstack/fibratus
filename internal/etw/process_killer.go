/*
 * Copyright 2021-present by Nedim Sabic Sabic
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

package etw

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/rules"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	log "github.com/sirupsen/logrus"
)

const (
	// defaultKillTTL is the time during which the process that was killed
	// isn't killed again, since the same match can be reported by many events
	defaultKillTTL = time.Minute
	// defaultMaxKills is the maximum number of kills within the kill window
	defaultMaxKills = 30
	// defaultKillWindow is the time window the kill limit is applied to
	defaultKillWindow = time.Minute
	// startTimeTolerance is the tolerance when comparing the process start
	// time from the event with the creation time of the live process
	startTimeTolerance = 2 * time.Second
)

var (
	// errPIDReused indicates the pid now belongs to a different process
	errPIDReused = errors.New("pid was reused by another process")
	// errKillRateLimited indicates the kill limit was reached
	errKillRateLimited = errors.New("kill rate limit reached")
)

// protectedProcesses are the critical system processes that are never
// terminated, since killing them takes down the whole machine.
var protectedProcesses = map[string]struct{}{
	"system":       {},
	"registry":     {},
	"smss.exe":     {},
	"csrss.exe":    {},
	"wininit.exe":  {},
	"winlogon.exe": {},
	"services.exe": {},
	"lsass.exe":    {},
}

// killTarget is the process selected for termination.
type killTarget struct {
	pid  uint32
	name string
	// started is the process start time, used to detect pid reuse.
	// It is zero if unknown.
	started time.Time
}

type killKey struct {
	pid     uint32
	started time.Time
}

// ProcessKiller terminates the processes that participated in the rule match.
// It implements the rules.ProcessKiller interface.
//
// Since killing processes is a destructive action that is driven by the
// detection logic, the killer is conservative:
//
//   - it never kills itself, the idle/system processes and the critical
//     system processes
//   - it verifies the process creation time before terminating it, so a
//     recycled pid can't result in an innocent process being killed
//   - the process that was recently killed is not killed again
//   - it disarms itself when too many processes are killed in a short period,
//     which prevents the buggy or too broad rule from taking the host down
type ProcessKiller struct {
	mu sync.Mutex

	// terminate terminates the process. It returns errPIDReused if the
	// start time doesn't match, and nil if the process doesn't exist anymore
	terminate func(pid uint32, started time.Time) error
	now       func() time.Time
	self      uint32

	ttl       time.Duration
	maxKills  int
	window    time.Duration
	recent    map[killKey]time.Time
	killTimes []time.Time
}

// ProcessKillerOption customizes the process killer.
type ProcessKillerOption func(*ProcessKiller)

// WithKillLimit sets the maximum number of kills allowed in the time window.
func WithKillLimit(max int, window time.Duration) ProcessKillerOption {
	return func(k *ProcessKiller) { k.maxKills, k.window = max, window }
}

// NewProcessKiller creates the process killer.
func NewProcessKiller(opts ...ProcessKillerOption) *ProcessKiller {
	k := &ProcessKiller{
		//terminate: terminateProcess,
		now:      time.Now,
		self:     uint32(os.Getpid()),
		ttl:      defaultKillTTL,
		maxKills: defaultMaxKills,
		window:   defaultKillWindow,
		recent:   make(map[killKey]time.Time),
	}
	for _, opt := range opts {
		opt(k)
	}
	return k
}

// Kill terminates the processes the matched events originate from. All the
// processes are attempted even if terminating some of them fails.
func (k *ProcessKiller) Kill(m rules.RuleMatch) error {
	var errs []error
	for _, t := range killTargets(m.Events) {
		if err := k.kill(m.Rule.Name, t); err != nil {
			errs = append(errs, err)
		}
	}
	return multierror.Wrap(errs...)
}

func (k *ProcessKiller) kill(rule string, t killTarget) error {
	if k.isProtected(t) {
		log.Warnf("[%s] refusing to kill protected process %s (pid %d)", rule, t.name, t.pid)
		return nil
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	now := k.now()
	k.expire(now)

	key := killKey{pid: t.pid, started: t.started}
	if _, ok := k.recent[key]; ok {
		log.Debugf("[%s] process %s (pid %d) was already killed", rule, t.name, t.pid)
		return nil
	}
	if len(k.killTimes) >= k.maxKills {
		return fmt.Errorf("unable to kill pid %d: %w", t.pid, errKillRateLimited)
	}

	err := k.terminate(t.pid, t.started)
	switch {
	case errors.Is(err, errPIDReused):
		log.Warnf("[%s] pid %d was reused by another process. The process won't be killed", rule, t.pid)
		return nil
	case err != nil:
		return err
	}

	k.recent[key] = now
	k.killTimes = append(k.killTimes, now)
	log.Infof("[%s] killed process %s (pid %d)", rule, t.name, t.pid)

	return nil
}

// expire forgets about the kills that fell out of the time windows.
func (k *ProcessKiller) expire(now time.Time) {
	for key, at := range k.recent {
		if now.Sub(at) > k.ttl {
			delete(k.recent, key)
		}
	}
	i := 0
	for i < len(k.killTimes) && now.Sub(k.killTimes[i]) > k.window {
		i++
	}
	k.killTimes = k.killTimes[i:]
}

func (k *ProcessKiller) isProtected(t killTarget) bool {
	if t.pid == 0 || t.pid == 4 || t.pid == k.self {
		return true
	}
	_, ok := protectedProcesses[strings.ToLower(t.name)]
	return ok
}

// killTargets selects the unique processes from the matched events. For the
// process creation, the target is the created process rather than the parent.
func killTargets(evts []*event.Event) []killTarget {
	var (
		targets []killTarget
		seen    = make(map[uint32]struct{})
	)
	for _, e := range evts {
		var t killTarget
		if e.IsCreateProcess() {
			pid, err := e.Params.GetPid()
			if err != nil {
				continue
			}
			name, _ := e.Params.GetString(params.ProcessName)
			t = killTarget{pid: pid, name: name, started: e.Timestamp}
		} else {
			t = killTarget{pid: e.PID}
			if e.PS != nil {
				t.name, t.started = e.PS.Name, e.PS.StartTime
			}
		}
		if _, ok := seen[t.pid]; ok {
			continue
		}
		seen[t.pid] = struct{}{}
		targets = append(targets, t)
	}
	return targets
}

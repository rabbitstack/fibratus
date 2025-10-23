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

package evasion

import (
	"expvar"

	"github.com/rabbitstack/fibratus/pkg/event"
	log "github.com/sirupsen/logrus"
)

var evasionsCount expvar.Map

// Scanner is responsible for evaluating evasion detectors
// and decorating the event with the reported behaviours.
// Some behaviours represent strong IoCs, while other need
// careful tuning to avoid alert fatigue. Evasion behaviours
// are consumed by the rule engine through the filter fields
// that yields the evasion techniques, such as direct syscall.
type Scanner struct {
	evasions []Evasion
}

// NewScanner instantiates the new evasion scanner.
func NewScanner(config Config) *Scanner {
	s := &Scanner{
		evasions: make([]Evasion, 0),
	}

	if config.EnableDirectSyscall {
		s.registerEvasion(NewDirectSyscall())
	}
	if config.EnableIndirectSyscall {
		s.registerEvasion(NewIndirectSyscall())
	}

	return s
}

func (s *Scanner) ProcessEvent(e *event.Event) (bool, error) {
	// filter out CreateFile events with the open disposition
	// as they tend to be noisy and could impact performance
	// when hitting evasion detectors
	if e.IsOpenDisposition() {
		return true, nil
	}

	var enq bool

	// run registered evasion detectors
	for _, evasion := range s.evasions {
		matches, err := evasion.Eval(e)
		if err != nil {
			return false, err
		}
		if matches {
			enq = true
			e.AddSliceMetaOrAppend(event.EvasionsKey, evasion.Type().String())
			evasionsCount.Add(evasion.Type().String(), 1)
			log.Debugf("detected evasion %q on event [%s] and callstack [%s]", evasion.Type(), e, e.Callstack)
		}
	}

	return enq, nil
}

func (s *Scanner) CanEnqueue() bool { return false }

func (s *Scanner) registerEvasion(evasion Evasion) {
	s.evasions = append(s.evasions, evasion)
}

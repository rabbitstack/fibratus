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
	"github.com/rabbitstack/fibratus/pkg/event"
	log "github.com/sirupsen/logrus"
)

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
	for _, eva := range s.evasions {
		matches, err := eva.Eval(e)
		if err != nil {
			return false, err
		}
		if matches {
			enq = true
			e.AddSliceMetaOrAppend(event.EvasionsKey, eva.Type().String())
			log.Infof("detected evasion %q on event [%s] and callstack [%s]", eva.Type(), e, e.Callstack)
		}
	}

	return enq, nil
}

func (s *Scanner) CanEnqueue() bool { return false }

func (s *Scanner) registerEvasion(eva Evasion) {
	s.evasions = append(s.evasions, eva)
}

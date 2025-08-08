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

type Scanner struct {
	config   Config
	evasions []Evasion
}

func NewScanner(config Config) *Scanner {
	s := &Scanner{
		config:   config,
		evasions: make([]Evasion, 0),
	}

	if config.EnableDirectSyscall {
		s.registerEvasion(NewDirectSyscall())
	}

	return s
}

func (s *Scanner) ProcessEvent(evt *event.Event) (bool, error) {
	// filter out CreateFile event with open disposition
	// as they tend to be noisy and could impact performance
	// when hitting evasion detectors
	if evt.IsOpenDisposition() {
		return true, nil
	}

	// run registered evasion detectors
	for _, eva := range s.evasions {
		matches, err := eva.Eval(evt)
		if err != nil {
			return true, err
		}
		if matches {
			// decorate the event with the detected evasion technique
			evt.AddSliceMetaOrAppend(event.EvasionsKey, eva.Type().String())
			log.Infof("detected evasion %q originating from the event %s and callstack %s", eva.Type(), evt, evt.Callstack)
		}
	}

	return true, nil
}

func (s *Scanner) CanEnqueue() bool { return s.config.EnqueueEvent }

func (s *Scanner) registerEvasion(eva Evasion) {
	s.evasions = append(s.evasions, eva)
}

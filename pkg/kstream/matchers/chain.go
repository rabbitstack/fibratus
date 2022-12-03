/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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

package matchers

import (
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/kevent"
)

type Chain interface {
	Match(*kevent.Kevent) (bool, error)
}

type chain struct {
	matchers []Matcher
}

func NewChain(config *config.Config) Chain {
	chain := &chain{matchers: make([]Matcher, 0)}

	chain.addMatcher(newNativeRules(config))

	if config.Yara.Enabled {
		chain.addMatcher(newYaraRules())
	}

	return chain
}

func (c *chain) addMatcher(m Matcher) {
	c.matchers = append(c.matchers, m)
}

func (c *chain) Match(kevt *kevent.Kevent) (bool, error) {
	var matches bool
	for _, m := range c.matchers {
		match, err := m.Match(kevt)
		if err != nil {
			return match, err
		}
		matches = match
	}
	if matches {
		return true, nil
	}
	return false, nil
}

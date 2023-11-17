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

package symbolize

import (
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/sys"
)

type Symbolizer struct {
	config *config.Config
}

func NewSymbolizer(config *config.Config) *Symbolizer {
	sys.SymSetOptions(sys.SymoptUndname)
	return &Symbolizer{config: config}
}

func (s *Symbolizer) ProcessEvent(e *kevent.Kevent) (bool, error) {
	if !e.Kparams.Contains(kparams.Callstack) ||
		(e.IsCreateFile() && e.Kparams.Contains(kparams.Callstack) && !e.IsCreateDisposition()) {
		return true, nil
	}

	return true, nil
}

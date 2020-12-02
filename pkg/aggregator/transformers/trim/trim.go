/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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

package trim

import (
	"github.com/rabbitstack/fibratus/pkg/aggregator/transformers"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"strings"
)

// trim transformer trims suffixes/prefixes from kpar values.
type trim struct {
	c Config
}

func init() {
	transformers.Register(transformers.Trim, initTrimTransformer)
}

func initTrimTransformer(config transformers.Config) (transformers.Transformer, error) {
	cfg, ok := config.Transformer.(Config)
	if !ok {
		return nil, transformers.ErrInvalidConfig(transformers.Trim)
	}
	return &trim{c: cfg}, nil
}

func (r trim) Transform(kevt *kevent.Kevent) error {
	for _, kpar := range kevt.Kparams {
		if kpar.Type != kparams.AnsiString && kpar.Type != kparams.UnicodeString {
			continue
		}
		// trim prefixes
		for _, par := range r.c.Prefixes {
			if kpar.Name != par.Name {
				continue
			}
			s, ok := kpar.Value.(string)
			if !ok {
				continue
			}
			kpar.Value = strings.TrimPrefix(s, par.Trim)
		}
		// trim suffixes
		for _, par := range r.c.Suffixes {
			if kpar.Name != par.Name {
				continue
			}
			s, ok := kpar.Value.(string)
			if !ok {
				continue
			}
			kpar.Value = strings.TrimSuffix(s, par.Trim)
		}
	}
	return nil
}

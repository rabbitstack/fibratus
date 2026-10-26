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
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"strings"
)

// trim transformer trims suffixes/prefixes from par values.
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

func (r trim) Transform(evt *event.Event) error {
	for i := range evt.Params {
		par := &evt.Params[i]
		if par.Value.Kind() != params.KindString {
			continue
		}
		name := par.Name()
		// trim prefixes
		for _, pre := range r.c.Prefixes {
			if name != pre.Name {
				continue
			}
			par.Value = params.Str(strings.TrimPrefix(par.String(), pre.Trim))
		}
		// trim suffixes
		for _, suf := range r.c.Suffixes {
			if name != suf.Name {
				continue
			}
			par.Value = params.Str(strings.TrimSuffix(par.String(), suf.Trim))
		}
	}
	return nil
}

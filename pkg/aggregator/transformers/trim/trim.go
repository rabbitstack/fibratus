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
	for _, par := range evt.Params {
		// trim prefixes
		for _, pre := range r.c.Prefixes {
			if par.Name != pre.Name {
				continue
			}
			_, ok := par.Value.(string)
			if !ok {
				continue
			}
			par.Value = strings.TrimPrefix(evt.GetParamAsString(par.Name), pre.Trim)
		}
		// trim suffixes
		for _, suf := range r.c.Suffixes {
			if par.Name != suf.Name {
				continue
			}
			_, ok := par.Value.(string)
			if !ok {
				continue
			}
			par.Value = strings.TrimSuffix(evt.GetParamAsString(par.Name), suf.Trim)
		}
	}
	return nil
}

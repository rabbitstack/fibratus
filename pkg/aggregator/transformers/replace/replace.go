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

package replace

import (
	"expvar"
	"github.com/rabbitstack/fibratus/pkg/aggregator/transformers"
	"github.com/rabbitstack/fibratus/pkg/event"
	"strings"
)

var replaceCount = expvar.NewInt("transformers.replaced.params")

// replace applies string substitutions in par values.
type replace struct {
	c Config
}

func init() {
	transformers.Register(transformers.Replace, initReplaceTransformer)
}

func initReplaceTransformer(config transformers.Config) (transformers.Transformer, error) {
	cfg, ok := config.Transformer.(Config)
	if !ok {
		return nil, transformers.ErrInvalidConfig(transformers.Replace)
	}
	return &replace{c: cfg}, nil
}

func (r replace) Transform(evt *event.Event) error {
	for _, repl := range r.c.Replacements {
		par := evt.Params.Find(repl.Param)
		if par == nil {
			continue
		}
		_, ok := par.Value.(string)
		if !ok {
			continue
		}
		par.Value = strings.ReplaceAll(evt.GetParamAsString(par.Name), repl.Old, repl.New)
		replaceCount.Add(1)
	}
	return nil
}

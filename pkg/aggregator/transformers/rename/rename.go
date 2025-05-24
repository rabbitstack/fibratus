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

package rename

import (
	"github.com/rabbitstack/fibratus/pkg/aggregator/transformers"
	"github.com/rabbitstack/fibratus/pkg/event"
)

// rename as it name implies, it renames a sequence of params to their new names.
type rename struct {
	c Config
}

func init() {
	transformers.Register(transformers.Rename, initRenameTransformer)
}

func initRenameTransformer(config transformers.Config) (transformers.Transformer, error) {
	cfg, ok := config.Transformer.(Config)
	if !ok {
		return nil, transformers.ErrInvalidConfig(transformers.Rename)
	}
	return &rename{c: cfg}, nil
}

func (r rename) Transform(evt *event.Event) error {
	for _, p := range r.c.Params {
		par, ok := evt.Params[p.Old]
		if !ok {
			continue
		}
		evt.Params.Remove(p.Old)
		par.Name = p.New
		evt.Params[p.New] = par
	}
	return nil
}

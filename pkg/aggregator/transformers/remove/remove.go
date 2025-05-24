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

package remove

import (
	"expvar"
	"github.com/rabbitstack/fibratus/pkg/aggregator/transformers"
	"github.com/rabbitstack/fibratus/pkg/event"
)

var removedCount = expvar.NewInt("transformers.removed.params")

// remove transformer deletes params that are given in the list.
type remove struct {
	c Config
}

func init() {
	transformers.Register(transformers.Remove, initRemoveTransformer)
}

func initRemoveTransformer(config transformers.Config) (transformers.Transformer, error) {
	cfg, ok := config.Transformer.(Config)
	if !ok {
		return nil, transformers.ErrInvalidConfig(transformers.Remove)
	}
	return &remove{c: cfg}, nil
}

func (r remove) Transform(evt *event.Event) error {
	for _, par := range r.c.Params {
		delete(evt.Params, par)
		removedCount.Add(1)
	}
	return nil
}

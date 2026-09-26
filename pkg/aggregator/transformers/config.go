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

package transformers

import (
	"fmt"

	"github.com/rabbitstack/fibratus/pkg/util/mapdecoder"
)

// ErrInvalidConfig signals an invalid transformer configuration
var ErrInvalidConfig = func(name Type) error { return fmt.Errorf("invalid config for %q transformer", name) }

// ConfigLoader decodes raw config for a single transformer type.
// enabled reports whether the transformer's Enabled flag was set.
type ConfigLoader func(any) (Config, bool, error)

// ConfigLoaders is the registry of configured transformers.
type ConfigLoaders map[Type]ConfigLoader

func (loaders ConfigLoaders) Register(typ Type, loader ConfigLoader) {
	if _, ok := loaders[typ]; ok {
		panic(fmt.Sprintf("transformer loader %q is already registered", typ))
	}
	loaders[typ] = loader
}

// Config acts as a container for the transformer configuration structures.
type Config struct {
	Type        Type
	Transformer any
}

// LoadFromConfig builds a transformer loader for a config type T, decoding
// raw into it and reporting whether the transformer is enabled.
func LoadFromConfig[T any](typ Type, enabled func(T) bool) ConfigLoader {
	return func(raw any) (Config, bool, error) {
		var cfg T
		if err := mapdecoder.Decode(raw, &cfg); err != nil {
			return Config{}, false, err
		}
		if !enabled(cfg) {
			return Config{}, false, nil
		}
		return Config{Type: typ, Transformer: cfg}, true, nil
	}
}

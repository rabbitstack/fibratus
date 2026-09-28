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

package alertsender

import (
	"fmt"

	"github.com/rabbitstack/fibratus/pkg/util/mapdecoder"
)

// ConfigLoader defines the alert sender configuration loader.
type ConfigLoader func(any) (Config, bool, error)

// Config is the container for the alert sender configuration structure.
type Config struct {
	Type   Type
	Sender any
}

// ConfigLoaders is the registry of configured alert senders.
type ConfigLoaders map[Type]ConfigLoader

// Register registers a new alert sender config loader.
func (loaders ConfigLoaders) Register(typ Type, loader ConfigLoader) {
	if _, ok := loaders[typ]; ok {
		panic(fmt.Sprintf("alertsender loader %q is already registered", typ))
	}
	loaders[typ] = loader
}

// LoadFromConfig builds a sender loader for a config type T, decoding
// raw into it and skipping it when the enabled predicate reports false.
func LoadFromConfig[T any](typ Type, enabled func(T) bool) ConfigLoader {
	return func(raw any) (Config, bool, error) {
		var cfg T
		if err := mapdecoder.Decode(raw, &cfg); err != nil {
			return Config{}, false, err
		}
		if !enabled(cfg) {
			return Config{}, false, nil
		}
		return Config{Type: typ, Sender: cfg}, true, nil
	}
}

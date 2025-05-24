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
	"github.com/rabbitstack/fibratus/pkg/event"
)

var transformers = map[Type]Factory{}

// Factory defines the function for transformer factories
type Factory func(config Config) (Transformer, error)

// Type defines the alias for the transformer types
type Type uint8

const (
	// Remove represents the remove transformer type. This transformer deletes the given list of parameters from the event.
	Remove Type = iota
	// Rename represents the rename transformer type. It renames a sequence of Param from old to new names.
	Rename
	// Replace represents the replace transformer type. It applies string replacements on specific params.
	Replace
	// Trim represents the trim transformer type that that removes suffix/prefix from string params.
	Trim
	// Tags represents the tags transformer type. This transformer appends tags to the event's metadata.
	Tags
)

// String returns the type human-readable name.
func (typ Type) String() string {
	switch typ {
	case Remove:
		return "remove"
	case Rename:
		return "rename"
	case Replace:
		return "replace"
	case Trim:
		return "trim"
	case Tags:
		return "tags"
	default:
		return "unknown"
	}
}

// Register registers a singleton instance of the provided transformer.
func Register(typ Type, factory Factory) {
	if _, ok := transformers[typ]; ok {
		panic(fmt.Sprintf("output %q is already registered", typ))
	}
	transformers[typ] = factory
}

// LoadAll loads all transformers from the configuration inputs.
func LoadAll(configs []Config) ([]Transformer, error) {
	transformers := make([]Transformer, len(configs))
	for i, config := range configs {
		transformer, err := Load(config)
		if err != nil {
			return nil, err
		}
		transformers[i] = transformer
	}
	return transformers, nil
}

// Load loads a single transformer from the configuration.
func Load(config Config) (Transformer, error) {
	typ := config.Type
	factory := transformers[typ]
	if factory == nil {
		return nil, fmt.Errorf("%q transformer not available in the factory", typ)
	}
	return factory(config)
}

// Transformer is the minimal interface all transformers have to satisfy.
type Transformer interface {
	Transform(*event.Event) error
}

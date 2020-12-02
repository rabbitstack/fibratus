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

package outputs

import (
	"fmt"
	"reflect"
	"strings"
)

var (
	outputs = map[Type]Factory{}
	// ErrInvalidConfig signals an invalid configuration input
	ErrInvalidConfig = func(name Type, c interface{}) error {
		return fmt.Errorf("invalid config for %q output. Got type %v instead of %s.Config", name, reflect.TypeOf(c), strings.ToLower(name.String()))
	}
)

type Factory func(config Config) (OutputGroup, error)

// Type is the alias for the output type.
type Type uint8

const (
	// Console represents the default terminal output.
	Console Type = iota
	AMQP
	Elasticsearch
	Null
)

// String returns the string representation of the output type.
func (t Type) String() string {
	switch t {
	case Console:
		return "console"
	case AMQP:
		return "amqp"
	case Elasticsearch:
		return "elasticsearch"
	case Null:
		return "null"
	default:
		return "unknown"
	}
}

type OutputGroup struct {
	Clients []Client
}

func Success(clients ...Client) OutputGroup {
	return OutputGroup{Clients: clients}
}

func Fail(err error) (OutputGroup, error) {
	return OutputGroup{}, err
}

func Register(typ Type, factory Factory) {
	if _, ok := outputs[typ]; ok {
		panic(fmt.Sprintf("output %q is already registered", typ))
	}
	outputs[typ] = factory
}

// FindFactory locates the output factory.
func FindFactory(typ Type) Factory {
	return outputs[typ]
}

func Load(typ Type, config Config) (OutputGroup, error) {
	factory := FindFactory(typ)
	if factory == nil {
		return OutputGroup{}, fmt.Errorf("output %q not availaible in the factory", typ)
	}
	return factory(config)
}

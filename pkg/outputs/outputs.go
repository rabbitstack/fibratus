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

// Factory serves for constructing different output implementations from configuration.
type Factory func(config Config) (OutputGroup, error)

// Type is the alias for the output type.
type Type uint8

const (
	// Console represents the default terminal output.
	Console Type = iota
	// AMQP denotes the AMQP output.
	AMQP
	// Elasticsearch denotes the Elasticsearch output.
	Elasticsearch
	// HTTP denotes the HTTP output.
	HTTP
	// Eventlog denotes the eventlog output.
	Eventlog
	// Null is the null output.
	Null
	// Unknown is an undefined output type.
	Unknown
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
	case HTTP:
		return "http"
	case Eventlog:
		return "eventlog"
	case Null:
		return "null"
	default:
		return "unknown"
	}
}

// TypeFromString parses output type from input string.
func TypeFromString(s string) Type {
	switch s {
	case "console":
		return Console
	case "amqp":
		return AMQP
	case "elasticsearch":
		return Elasticsearch
	case "http":
		return HTTP
	case "eventlog":
		return Eventlog
	case "null":
		return Null
	default:
		return Unknown
	}
}

// Serializer is the type definition for the output serializers.
type Serializer uint8

const (
	// JSON represents the JSON serializer type.
	JSON Serializer = iota
	// XML represents the XML serializer type.
	XML
	// Text represents the textual form serializer type.
	Text
)

// String returns the string representation of the serializer type.
func (s Serializer) String() string {
	switch s {
	case JSON:
		return "json"
	case XML:
		return "xml"
	case Text:
		return "text"
	default:
		panic(fmt.Sprintf("unrecognized serializer identifier: %d", s))
	}
}

// OutputGroup is a collection of outputs that can be configured in a load-balanced fashion.
type OutputGroup struct {
	// Clients is the list of clients to which events are forwarded.
	Clients []Client
}

// Success builds the output group from the provided clients.
func Success(clients ...Client) OutputGroup {
	return OutputGroup{Clients: clients}
}

// Fail returns an empty output group and an error signaling the failure that caused the output group initialization.
func Fail(err error) (OutputGroup, error) {
	return OutputGroup{}, err
}

// Register registers a new output implementation. Note this function should be only called once per output.
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

// Load loads the specified output from configuration. The output must have been registered previously.
func Load(typ Type, config Config) (OutputGroup, error) {
	factory := FindFactory(typ)
	if factory == nil {
		return OutputGroup{}, fmt.Errorf("output %q not availaible in the factory", typ)
	}
	return factory(config)
}

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

import "fmt"

// ErrInvalidConfig signals an invalid sender config
var ErrInvalidConfig = func(name Type) error { return fmt.Errorf("invalid config for %q sender", name) }

var factories = map[Type]Factory{}
var alertsenders = map[Type]Sender{}

// Factory defines the alias for the alert sender factory
type Factory func(config Config) (Sender, error)

// Type defines the alias for the alert sender type
type Type uint8

const (
	// Mail designates mail alert sender
	Mail Type = iota
	// Slack designates Slack alert sender
	Slack
	// Noop is a noop alert sender. Useful for testing.
	Noop
	// None is the type for unknown alert sender
	None
)

// String returns the string representation of the alert sender type.
func (s Type) String() string {
	switch s {
	case Mail:
		return "mail"
	case Slack:
		return "slack"
	case Noop:
		return "noop"
	default:
		return "none"
	}
}

// Sender is the minimal interface all alert senders have to implement.
type Sender interface {
	// Send emits an alert.
	Send(Alert) error
	// Type returns the type that identifies a particular sender.
	Type() Type
}

// ToType converts the string representation of the alert sender to its corresponding type.
func ToType(s string) Type {
	switch s {
	case "mail":
		return Mail
	case "slack":
		return Slack
	case "noop":
		return Noop
	default:
		return None
	}
}

// Register registers a new alert sender.
func Register(typ Type, factory Factory) {
	if _, ok := factories[typ]; ok {
		panic(fmt.Sprintf("%q alert sender is already registered", typ))
	}
	factories[typ] = factory
}

// Find locates the sender.
func Find(typ Type) Sender {
	return alertsenders[typ]
}

// FindAll returns all registered senders.
func FindAll() []Sender {
	senders := make([]Sender, 0, len(alertsenders))
	for _, s := range alertsenders {
		senders = append(senders, s)
	}
	return senders
}

// Load loads an alert sender from the registry.
func Load(config Config) (Sender, error) {
	typ := config.Type
	factory := factories[typ]
	if factory == nil {
		return nil, fmt.Errorf("%q alert sender not availaible in the factory", typ)
	}
	return factory(config)
}

// LoadAll loads all alert senders from the configuration inputs.
func LoadAll(configs []Config) error {
	for _, config := range configs {
		alertsender, err := Load(config)
		if err != nil {
			return fmt.Errorf("fail to load %q alertsender: %v", config.Type, err)
		}
		alertsenders[config.Type] = alertsender
	}
	return nil
}

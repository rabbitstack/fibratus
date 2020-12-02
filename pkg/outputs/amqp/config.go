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

package amqp

import (
	"github.com/rabbitstack/fibratus/pkg/outputs"
	"github.com/spf13/pflag"
	"github.com/streadway/amqp"
	"time"
)

const (
	amqpURI          = "output.amqp.url"
	amqpTimeout      = "output.amqp.timeout"
	amqpVhost        = "output.amqp.vhost"
	amqpExchange     = "output.amqp.exchange"
	amqpRoutingKey   = "output.amqp.routing-key"
	amqpExchangeType = "output.amqp.exchange-type"
	amqpEnabled      = "output.amqp.enabled"
	amqpPassive      = "output.amqp.passive"
	amqpDurable      = "output.amqp.durable"
	amqpDeliveryMode = "output.amqp.delivery-mode"
	amqpUsername     = "output.amqp.username"
	amqpPassword     = "output.amqp.password"
)

// Config contains the tweaks that influence the behaviour of the AMQP output.
type Config struct {
	outputs.TLSConfig
	// Enabled indicates if the AMQP output is enabled
	Enabled bool `mapstructure:"enabled"`
	// URL represents the AMQP connection string.
	URL string `mapstructure:"url"`
	// Timeout specifies the AMQP connection timeout.
	Timeout time.Duration `mapstructure:"timeout"`
	// Exchange is the AMQP exchange for publishing events.
	Exchange string `mapstructure:"exchange"`
	// ExchangeType is the AMQP exchange type.
	ExchangeType string `mapstructure:"exchange-type"`
	// Passive indicates that the server checks whether the exchange already exists and raises an error if it doesn't exist.
	Passive bool `mapstructure:"passive"`
	// Durable indicates that the exchange is marked as durable. Durable exchanges can survive server restarts.
	Durable bool `mapstructure:"durable"`
	// DeliveryMode determines if a published message is persistent or transient.
	DeliveryMode string `mapstructure:"delivery-mode"`
	// RoutingKey represents the static routing key to link exchanges with queues.
	RoutingKey string `mapstructure:"routing-key"`
	// Username is the username for the plain authentication method.
	Username string `mapstructure:"username"`
	// Password is the password for the plain authentication method.
	Password string `mapstructure:"password"`
	// Vhost represents the virtual host name.
	Vhost string `mapstructure:"vhost"`
	// Headers contains a list of headers that are added to AMQP message
	Headers map[string]string `mapstructure:"headers"`
}

// AddFlags registers persistent flags.
func AddFlags(flags *pflag.FlagSet) {
	flags.String(amqpURI, "amqp://localhost:5672", "Represents the AMQP broker address")
	flags.Duration(amqpTimeout, time.Second*5, "Specifies the AMQP connection timeout")
	flags.String(amqpVhost, "/", "The virtual host that provides logical grouping and separation of broker's resources")
	flags.String(amqpExchange, "fibratus", "Specifies the target exchange name")
	flags.String(amqpExchangeType, "topic", "Defines the AMQP exchange type")
	flags.String(amqpRoutingKey, "fibratus", "Specifies the routing key")
	flags.Bool(amqpDurable, false, "Indicates if the exchange is marked as durable. Durable exchanges can survive server restarts.")
	flags.Bool(amqpPassive, false, "Indicates if the server checks whether the exchange already exists and raises an error if it doesn't exist.")
	flags.Bool(amqpEnabled, false, "Indicates if the AMQP output is enabled")
	flags.String(amqpDeliveryMode, "transient", "Determines if a published message is persistent or transient")
	flags.String(amqpUsername, "", "The username for the plain authentication method")
	flags.String(amqpPassword, "", "The password for the plain authentication method")
	outputs.AddTLSFlags(flags, outputs.AMQP)
}

func (c Config) amqpHeaders() amqp.Table {
	headers := make(amqp.Table)
	for k, v := range c.Headers {
		headers[k] = v
	}
	return headers
}

func (c Config) deliveryMode() uint8 {
	switch c.DeliveryMode {
	case "transient":
		return amqp.Transient
	case "persistent":
		return amqp.Persistent
	default:
		return amqp.Transient
	}
}

func (c Config) auth() []amqp.Authentication {
	if c.Username == "" && c.Password == "" {
		return nil
	}
	return []amqp.Authentication{
		&amqp.PlainAuth{
			Username: c.Username,
			Password: c.Password,
		},
	}
}

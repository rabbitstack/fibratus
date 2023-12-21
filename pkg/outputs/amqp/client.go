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
	"expvar"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/util/tls"
	log "github.com/sirupsen/logrus"
	"github.com/streadway/amqp"
	"net"
	"sync"
	"time"
)

var (
	connectionFailures = expvar.NewInt("output.amqp.connection.failures")
	channelFailures    = expvar.NewInt("output.amqp.channel.failures")
)

// client encapsulates the AMQP connection/channel and deals with configuring, establishing the connection
// and publishing messages to the exchange.
type client struct {
	conn     *amqp.Connection
	connLock sync.Mutex

	channel *amqp.Channel
	config  Config
	quit    chan struct{}
}

// newClient creates a new AMQP client and setups the connection/channel.
func newClient(config Config) *client {
	return &client{config: config, quit: make(chan struct{})}
}

// connect opens a connection to the AMQP broker honoring the preferences that were passed in the config.
func (c *client) connect(healthcheck bool) error {
	amqpConfig := amqp.Config{
		Vhost: c.config.Vhost,
		Dial: func(network, addr string) (net.Conn, error) {
			return net.DialTimeout(network, addr, c.config.Timeout)
		},
		SASL: c.config.auth(),
	}
	tlsConfig, err := tls.MakeConfig(c.config.TLSCert, c.config.TLSKey, c.config.TLSCA, c.config.TLSInsecureSkipVerify)
	if err != nil {
		return fmt.Errorf("invalid TLS config: %v", err)
	}
	amqpConfig.TLSClientConfig = tlsConfig

	c.connLock.Lock()
	defer c.connLock.Unlock()
	c.conn, err = amqp.DialConfig(c.config.URL, amqpConfig)
	if err != nil {
		return err
	}
	c.channel, err = c.conn.Channel()
	if err != nil {
		return fmt.Errorf("unable to open AMQP channel: %v", err)
	}

	log.Infof("established connection to AMQP broker on %s", c.config.URL)

	if healthcheck {
		go c.doHealthcheck()
	}

	return nil
}

// declareExchange creates the exchange in the broker where messages are published.
func (c *client) declareExchange() error {
	c.connLock.Lock()
	defer c.connLock.Unlock()
	var err error
	if c.config.Passive {
		err = c.channel.ExchangeDeclarePassive(
			c.config.Exchange,
			c.config.ExchangeType,
			c.config.Durable,
			false,
			false,
			false,
			nil,
		)
	} else {
		err = c.channel.ExchangeDeclare(
			c.config.Exchange,
			c.config.ExchangeType,
			c.config.Durable,
			false,
			false,
			false,
			nil,
		)
	}
	if err != nil {
		return fmt.Errorf("unable to declare %s exchange: %v", c.config.Exchange, err)
	}
	return nil
}

// publish sends the byte stream to the exchange.
func (c *client) publish(body []byte) error {
	return c.channel.Publish(c.config.Exchange, c.config.RoutingKey, false, false, c.msg(body))
}

func (c *client) msg(body []byte) amqp.Publishing {
	return amqp.Publishing{
		Body:         body,
		ContentType:  "text/json",
		Headers:      c.config.amqpHeaders(),
		DeliveryMode: c.config.deliveryMode(),
	}
}

// healthcheck monitors the state of the AMQP connection and its corresponding channel. Since AMQP channel is
// shutdown if an error occurs on it, we'll have to handle this situation properly and try to reopen the channel.
// Similarly, if the connection is lost, the reconnect loop kicks in and tries to reconcile the connection state.
func (c *client) doHealthcheck() {
	notify := c.conn.NotifyClose(make(chan *amqp.Error))
	cnotify := c.channel.NotifyClose(make(chan *amqp.Error))
	go func() {
		for {
			select {
			case err := <-cnotify:
				if err != nil {
					channelFailures.Add(1)
					log.Warnf("channel error: %v. Trying to reopen...", err)
					c.connLock.Lock()
					if c.conn != nil && !c.conn.IsClosed() {
						for {
							var err error
							c.channel, err = c.conn.Channel()
							if err == nil {
								log.Info("channel reopened")
								cnotify = c.channel.NotifyClose(make(chan *amqp.Error))
								break
							}
							// sleep a bit before retrying
							time.Sleep(time.Millisecond * 500)
						}
					}
					c.connLock.Unlock()
				}
			case <-c.quit:
				return
			}
		}
	}()

	for {
		select {
		case err := <-notify:
			if err != nil {
				for {
					connectionFailures.Add(1)
					log.Warnf("connection error: %v. Trying to reconnect...", err)
					e := c.connect(false)
					if e == nil {
						log.Info("connection recovered")
						c.connLock.Lock()
						notify = c.conn.NotifyClose(make(chan *amqp.Error))
						c.connLock.Unlock()
						break
					}
				}
			}
		case <-c.quit:
			return
		}
	}
}

// close tears down the underlying AMQP connection.
func (c *client) close() error {
	if c.conn == nil {
		return nil
	}
	close(c.quit)
	c.connLock.Lock()
	defer c.connLock.Unlock()
	err := c.conn.Close()
	if err != nil && err != amqp.ErrClosed {
		return err
	}
	return nil
}

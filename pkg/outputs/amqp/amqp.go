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

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/outputs"
)

var (
	// amqpErrors counts AMQP delivery errors
	amqpErrors = expvar.NewInt("output.amqp.publish.errors")
	// amqpMessages counts the total number of published messages
	amqpMessages = expvar.NewInt("output.amqp.publish.messages")
)

type rabbitmq struct {
	client *client
}

func init() {
	outputs.Register(outputs.AMQP, initAMQP)
}

func initAMQP(config outputs.Config) (outputs.OutputGroup, error) {
	cfg, ok := config.Output.(Config)
	if !ok {
		return outputs.Fail(outputs.ErrInvalidConfig(outputs.AMQP, config.Output))
	}

	q := &rabbitmq{client: newClient(cfg)}

	return outputs.Success(q), nil
}

func (q *rabbitmq) Connect() error {
	err := q.client.connect(true)
	if err != nil {
		return err
	}
	return q.client.declareExchange()
}

func (q *rabbitmq) Close() error {
	if q.client == nil {
		return nil
	}
	return q.client.close()
}

func (q *rabbitmq) Publish(batch *event.Batch) error {
	body := batch.MarshalJSON()

	err := q.client.publish(body)
	if err != nil {
		amqpErrors.Add(1)
		return err
	}

	amqpMessages.Add(1)

	return nil
}

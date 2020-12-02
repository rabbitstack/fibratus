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

package config

import (
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestOutput(t *testing.T) {
	c := NewWithOpts(WithRun())

	err := c.flags.Parse([]string{"--config-file=_fixtures/output.yml"})
	require.NoError(t, c.viper.BindPFlags(c.flags))
	require.NoError(t, err)
	require.NoError(t, c.TryLoadFile(c.GetConfigFile()))

	require.NoError(t, c.Init())

	require.NotNil(t, c.Output)
	require.IsType(t, amqp.Config{}, c.Output.Output)

	amqpConfig := c.Output.Output.(amqp.Config)
	assert.Equal(t, "amqp://localhost:5672", amqpConfig.URL)
	assert.Equal(t, time.Second*5, amqpConfig.Timeout)
	assert.Equal(t, "fibratus", amqpConfig.Exchange)
	assert.Equal(t, "topic", amqpConfig.ExchangeType)
	assert.Equal(t, "fibratus", amqpConfig.RoutingKey)
	assert.Equal(t, "/", amqpConfig.Vhost)
}

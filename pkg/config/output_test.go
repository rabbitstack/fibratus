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
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/outputs/eventlog"

	"github.com/rabbitstack/fibratus/pkg/outputs/amqp"
	"github.com/rabbitstack/fibratus/pkg/outputs/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAMQPOutput(t *testing.T) {
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

func TestHTTPOutput(t *testing.T) {
	c := NewWithOpts(WithRun())

	err := c.flags.Parse([]string{"--config-file=_fixtures/http-output.yml"})
	require.NoError(t, c.viper.BindPFlags(c.flags))
	require.NoError(t, err)
	require.NoError(t, c.TryLoadFile(c.GetConfigFile()))

	require.NoError(t, c.Init())

	require.NotNil(t, c.Output)
	require.IsType(t, http.Config{}, c.Output.Output)

	httpConfig := c.Output.Output.(http.Config)
	assert.True(t, httpConfig.Enabled)
	assert.Len(t, httpConfig.Endpoints, 2)
	assert.Contains(t, httpConfig.Endpoints, "http://localhost:8081")
	assert.Equal(t, time.Second*2, httpConfig.Timeout)
	assert.Equal(t, "http://192.168.1.8:3123", httpConfig.ProxyURL)
	assert.Equal(t, "bunny", httpConfig.ProxyUsername)
	assert.Equal(t, "bunny", httpConfig.ProxyPassword)
	assert.True(t, httpConfig.EnableGzip)
	assert.Equal(t, "basic", httpConfig.Username)
	assert.Equal(t, "basic", httpConfig.Password)
	assert.Len(t, httpConfig.Headers, 2)
	assert.Equal(t, "kkvvkk", httpConfig.Headers["api-key"])
}

func TestEventlogOutput(t *testing.T) {
	c := NewWithOpts(WithRun())

	err := c.flags.Parse([]string{"--config-file=_fixtures/eventlog-output.yml"})
	require.NoError(t, c.viper.BindPFlags(c.flags))
	require.NoError(t, err)
	require.NoError(t, c.TryLoadFile(c.GetConfigFile()))

	require.NoError(t, c.Init())

	require.NotNil(t, c.Output)
	require.IsType(t, eventlog.Config{}, c.Output.Output)

	eventlogConfig := c.Output.Output.(eventlog.Config)
	assert.True(t, eventlogConfig.Enabled)
	assert.Equal(t, "INFO", eventlogConfig.Level)
}

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
	"errors"
	"fmt"
	"reflect"
	"strconv"

	"github.com/rabbitstack/fibratus/pkg/outputs"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp"
	"github.com/rabbitstack/fibratus/pkg/outputs/console"
	"github.com/rabbitstack/fibratus/pkg/outputs/elasticsearch"
	"github.com/rabbitstack/fibratus/pkg/outputs/http"
	"github.com/rabbitstack/fibratus/pkg/outputs/null"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/svc"
)

var errNoOutputSection = errors.New("no output section in config")

var errOutputConfig = func(output string, err error) error { return fmt.Errorf("%s output invalid config: %v", output, err) }

func (c *Config) tryLoadOutput() error {
	output := c.viper.AllSettings()["output"]
	if output == nil {
		return errNoOutputSection
	}
	mapping, ok := output.(map[string]interface{})
	if !ok {
		return fmt.Errorf("expected map[string]interface{} type for output but found %s", reflect.TypeOf(output))
	}

	humNum := func(n int) string {
		switch n {
		case 2:
			return "two"
		case 3:
			return "three"
		case 4:
			return "four"
		case 5:
			return "five"
		case 6:
			return "six"
		case 7:
			return "seven"
		default:
			return strconv.Itoa(n)
		}
	}
	// don't permit if there are various outputs enabled at a time
	activeOutputs := findActiveOutputs(mapping)
	if len(activeOutputs) > 1 {
		return fmt.Errorf("expected one but found %s active outputs: %s", humNum(len(activeOutputs)), activeOutputs)
	}

	for typ, config := range mapping {
		switch outputs.TypeFromString(typ) {
		case outputs.Console:
			var consoleConfig console.Config
			if err := decode(config, &consoleConfig); err != nil {
				return errOutputConfig(typ, err)
			}
			if !consoleConfig.Enabled {
				continue
			}
			c.Output.Type, c.Output.Output = outputs.Console, consoleConfig

		case outputs.AMQP:
			var amqpConfig amqp.Config
			if err := decode(config, &amqpConfig); err != nil {
				return errOutputConfig(typ, err)
			}
			if !amqpConfig.Enabled {
				continue
			}
			c.Output.Type, c.Output.Output = outputs.AMQP, amqpConfig

		case outputs.Elasticsearch:
			var esConfig elasticsearch.Config
			if err := decode(config, &esConfig); err != nil {
				return errOutputConfig(typ, err)
			}
			if !esConfig.Enabled {
				continue
			}
			c.Output.Type, c.Output.Output = outputs.Elasticsearch, esConfig

		case outputs.HTTP:
			var httpConfig http.Config
			if err := decode(config, &httpConfig); err != nil {
				return errOutputConfig(typ, err)
			}
			if !httpConfig.Enabled {
				continue
			}
			c.Output.Type, c.Output.Output = outputs.HTTP, httpConfig
		}
	}

	// if it is not an interactive session but the console output is enabled
	// we default to null output and warn about that
	if isWindowsService() && c.Output.Output != nil {
		if c.Output.Type == outputs.Console {
			log.Warn("running in non-interactive session with console output. " +
				"Please configure a different output type. Defaulting to null output")
			c.Output.Type, c.Output.Output = outputs.Null, &null.Config{}
			return nil
		}
	}

	// default to null output
	if c.Output.Output == nil {
		log.Warn("all outputs disabled. Defaulting to null output")
		c.Output.Type, c.Output.Output = outputs.Null, &null.Config{}
	}

	return nil
}

func findActiveOutputs(outputs map[string]interface{}) []string {
	outputTypes := make([]string, 0)
	for typ, rawConfig := range outputs {
		enabled, ok := rawConfig.(map[string]interface{})["enabled"].(bool)
		if ok && enabled {
			outputTypes = append(outputTypes, typ)
		}
	}
	return outputTypes
}

// isWindowsService returns true if the process is running inside Windows Service.
func isWindowsService() bool {
	interactive, err := svc.IsAnInteractiveSession()
	if err != nil {
		return false
	}
	return !interactive
}

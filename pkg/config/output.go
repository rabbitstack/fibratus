/*
 * Copyright 2019-2026 by Nedim Sabic Sabic
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
	"strings"

	"github.com/rabbitstack/fibratus/pkg/outputs"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp"
	"github.com/rabbitstack/fibratus/pkg/outputs/console"
	"github.com/rabbitstack/fibratus/pkg/outputs/elasticsearch"
	"github.com/rabbitstack/fibratus/pkg/outputs/http"
	"github.com/rabbitstack/fibratus/pkg/outputs/null"
)

var ErrNoOutputSection = errors.New("no output section in config")

var ErrOutputConfig = func(output outputs.Type, err error) error {
	return fmt.Errorf("%s output invalid config: %v", output, err)
}

var outs = outputs.ConfigLoaders{}

func init() {
	outs.Register(outputs.Console, outputs.LoadFromConfig[console.Config](outputs.Console))
	outs.Register(outputs.AMQP, outputs.LoadFromConfig[amqp.Config](outputs.AMQP))
	outs.Register(outputs.Elasticsearch, outputs.LoadFromConfig[elasticsearch.Config](outputs.Elasticsearch))
	outs.Register(outputs.HTTP, outputs.LoadFromConfig[http.Config](outputs.HTTP))
}

// TryLoadOutput attempts the locate an active output config and load it.
func (c *BaseConfig) TryLoadOutput() error {
	output := c.viper.AllSettings()["output"]
	if output == nil {
		return ErrNoOutputSection
	}

	mapping, ok := output.(map[string]any)
	if !ok {
		return fmt.Errorf("expected map[string]interface{} type for output but found %s", reflect.TypeOf(output))
	}

	active, err := findActiveOutput(mapping)
	if err != nil {
		return err
	}

	switch active {
	case "":
		c.Output.Type, c.Output.Output = outputs.Null, &null.Config{}
	default:
		typ := outputs.TypeFromString(active)
		loader, ok := outs[typ]
		if !ok {
			return fmt.Errorf("unknown output type %q", typ)
		}
		c.Output, err = loader(mapping[active])
		if err != nil {
			return ErrOutputConfig(typ, err)
		}
	}
	return nil
}

// findActiveOutput returns an error if there are various outputs enabled
// at a time or either returns the active output name or an empty string if
// no outputs are enabled.
func findActiveOutput(mapping map[string]interface{}) (string, error) {
	active := make([]string, 0, len(mapping))
	for typ, raw := range mapping {
		output, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if enabled, _ := output["enabled"].(bool); enabled {
			active = append(active, typ)
		}
	}
	switch {
	case len(active) > 1:
		return "", fmt.Errorf("expected one but found %d active outputs: %s", len(active), strings.Join(active, ", "))
	case len(active) == 0:
		return "", nil
	case len(active) == 1:
		return active[0], nil
	}
	return "", nil
}

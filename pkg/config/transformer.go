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
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/aggregator/transformers"
	"github.com/rabbitstack/fibratus/pkg/aggregator/transformers/remove"
	"github.com/rabbitstack/fibratus/pkg/aggregator/transformers/rename"
	"github.com/rabbitstack/fibratus/pkg/aggregator/transformers/replace"
	"github.com/rabbitstack/fibratus/pkg/aggregator/transformers/tags"
	"github.com/rabbitstack/fibratus/pkg/aggregator/transformers/trim"
	"reflect"
)

var errTransformerConfig = func(t string, err error) error { return fmt.Errorf("%s transformer invalid config: %v", t, err) }

func (c *Config) tryLoadTransformers() error {
	transforms := c.viper.AllSettings()["transformers"]
	if transforms == nil {
		return nil
	}
	mapping, ok := transforms.(map[string]interface{})
	if !ok {
		return fmt.Errorf("expected map[string]interface{} type for transformers but found %s", reflect.TypeOf(transforms))
	}

	configs := make([]transformers.Config, 0)

	for typ, config := range mapping {
		switch typ {
		case "remove":
			var removeConfig remove.Config
			if err := decode(config, &removeConfig); err != nil {
				return errTransformerConfig(typ, err)
			}
			if !removeConfig.Enabled {
				continue
			}
			config := transformers.Config{
				Type:        transformers.Remove,
				Transformer: removeConfig,
			}
			configs = append(configs, config)

		case "rename":
			var renameConfig rename.Config
			if err := decode(config, &renameConfig); err != nil {
				return errTransformerConfig(typ, err)
			}
			if !renameConfig.Enabled {
				continue
			}
			config := transformers.Config{
				Type:        transformers.Rename,
				Transformer: renameConfig,
			}
			configs = append(configs, config)

		case "replace":
			var replaceConfig replace.Config
			if err := decode(config, &replaceConfig); err != nil {
				return errTransformerConfig(typ, err)
			}
			if !replaceConfig.Enabled {
				continue
			}
			config := transformers.Config{
				Type:        transformers.Replace,
				Transformer: replaceConfig,
			}
			configs = append(configs, config)

		case "trim":
			var trimConfig trim.Config
			if err := decode(config, &trimConfig); err != nil {
				return errTransformerConfig(typ, err)
			}
			if !trimConfig.Enabled {
				continue
			}
			config := transformers.Config{
				Type:        transformers.Trim,
				Transformer: trimConfig,
			}
			configs = append(configs, config)

		case "tags":
			var tagsConfig tags.Config
			if err := decode(config, &tagsConfig); err != nil {
				return errTransformerConfig(typ, err)
			}
			if !tagsConfig.Enabled {
				continue
			}
			config := transformers.Config{
				Type:        transformers.Tags,
				Transformer: tagsConfig,
			}
			configs = append(configs, config)
		}
	}

	c.Transformers = configs

	return nil
}

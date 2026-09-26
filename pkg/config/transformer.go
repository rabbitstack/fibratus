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
	"reflect"

	"github.com/rabbitstack/fibratus/pkg/aggregator/transformers"
	"github.com/rabbitstack/fibratus/pkg/aggregator/transformers/remove"
	"github.com/rabbitstack/fibratus/pkg/aggregator/transformers/rename"
	"github.com/rabbitstack/fibratus/pkg/aggregator/transformers/replace"
	"github.com/rabbitstack/fibratus/pkg/aggregator/transformers/tags"
	"github.com/rabbitstack/fibratus/pkg/aggregator/transformers/trim"
)

var ErrTransformerConfig = func(t string, err error) error { return fmt.Errorf("%s transformer invalid config: %v", t, err) }

var trans = transformers.ConfigLoaders{}

func init() {
	trans.Register(transformers.Remove, transformers.LoadFromConfig[remove.Config](transformers.Remove, func(c remove.Config) bool { return c.Enabled }))
	trans.Register(transformers.Rename, transformers.LoadFromConfig[rename.Config](transformers.Rename, func(c rename.Config) bool { return c.Enabled }))
	trans.Register(transformers.Replace, transformers.LoadFromConfig[replace.Config](transformers.Replace, func(c replace.Config) bool { return c.Enabled }))
	trans.Register(transformers.Trim, transformers.LoadFromConfig[trim.Config](transformers.Trim, func(c trim.Config) bool { return c.Enabled }))
	trans.Register(transformers.Tags, transformers.LoadFromConfig[tags.Config](transformers.Tags, func(c tags.Config) bool { return c.Enabled }))
}

// TryLoadTransformers attempts to load all registered transformer configs.
func (c *BaseConfig) TryLoadTransformers() error {
	transforms := c.viper.AllSettings()["transformers"]
	if transforms == nil {
		return nil
	}
	mapping, ok := transforms.(map[string]interface{})
	if !ok {
		return fmt.Errorf("expected map[string]interface{} type for transformers but found %s", reflect.TypeOf(transforms))
	}

	configs := make([]transformers.Config, 0, len(mapping))
	for typ, raw := range mapping {
		loader, ok := trans[transformers.TypeFromString(typ)]
		if !ok {
			return fmt.Errorf("unknown transformer type %q", typ)
		}
		cfg, enabled, err := loader(raw)
		if err != nil {
			return ErrTransformerConfig(typ, err)
		}
		if !enabled {
			continue
		}
		configs = append(configs, cfg)
	}

	c.Transformers = configs

	return nil
}

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

package tags

import (
	"github.com/rabbitstack/fibratus/pkg/aggregator/transformers"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"os"
	"strings"
)

// tags transformer appends tags to the event's metadata. It is capable of adding literal values as well as
// tags that are stored in environment variables.
type tags struct {
	tags map[string]string
}

func init() {
	transformers.Register(transformers.Tags, initTagsTransformer)
}

func initTagsTransformer(config transformers.Config) (transformers.Transformer, error) {
	cfg, ok := config.Transformer.(Config)
	if !ok {
		return nil, transformers.ErrInvalidConfig(transformers.Tags)
	}

	ktags := make(map[string]string)

	for _, tag := range cfg.Tags {
		// if the value is enclosed within % symbols this means
		// we have to expand it from the environ variable
		key, val := tag.Key, tag.Value
		if len(val) == 0 {
			continue
		}
		if val[0] == '%' && val[len(val)-1] == '%' {
			ktags[key] = os.Getenv(strings.ReplaceAll(val, "%", ""))
			continue
		}
		ktags[key] = val
	}

	return &tags{tags: ktags}, nil
}

func (t tags) Transform(kevt *kevent.Kevent) error {
	for k, v := range t.tags {
		kevt.AddMeta(k, v)
	}
	return nil
}

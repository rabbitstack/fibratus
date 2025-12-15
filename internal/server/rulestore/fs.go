/*
 * Copyright 2019-present by Nedim Sabic Sabic
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

package rulestore

import (
	"context"

	rulesapi "github.com/rabbitstack/fibratus/api/protobuf/rules/v1"
	"github.com/rabbitstack/fibratus/pkg/rules"
)

type fs struct {
	loader *rules.Loader
}

func NewFS() Store {
	return &fs{
		loader: rules.NewLoader(),
	}
}

func (s *fs) List() (*rulesapi.RuleSet, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rs, err := s.loader.Load(ctx,
		rules.WithRulePaths("C:\\Fibratus\\fibratus\\rules\\*.yml"),
		rules.WithMacroPaths("C:\\Fibratus\\fibratus\\rules\\macros\\*.yml"))
	if err != nil {
		return nil, err
	}
	return rs.ToProto(), nil
}

func (s *fs) Watch() (<-chan *rulesapi.RuleSet, <-chan error) {
	return nil, nil
}

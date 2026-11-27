/*
 * Copyright 2026 by Nedim Sabic Sabic
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

//go:build !yara

package eval

import (
	"fmt"

	errs "github.com/rabbitstack/fibratus/pkg/errors"
)

func newYaraEvaluator([]Evaluator) (Evaluator, error) {
	return nil, fmt.Errorf("yara function is not supported. %w", errs.ErrFeatureUnsupported("yara"))
}

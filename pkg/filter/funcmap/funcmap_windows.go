/*
 * Copyright 2020-2021 by Nedim Sabic Sabic
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

package funcmap

import (
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/filter/action"
	"text/template"
)

// New returns the template func map
// populated with some useful template functions
// that can be used in rule actions. Some functions
// are late-bound, so we merely provide a declaration.
// The real function is attached when the filter action
// is triggered.
func New() template.FuncMap {
	return config.FilterFuncMap()
}

// InitFuncs assigns late-bound functions to the func map.
func InitFuncs(funcMap template.FuncMap) {
	funcMap["emit"] = emit
	funcMap["kill"] = kill
}

// emit sends the rule alert via all configured alert senders.
func emit(ctx *config.ActionContext, title string, text string, args ...string) string {
	err := action.Emit(ctx, title, text, args...)
	if err != nil {
		return err.Error()
	}
	return ""
}

// kill terminates a process with specified pid.
func kill(pid uint32) string {
	err := action.Kill(pid)
	if err != nil {
		return err.Error()
	}
	return ""
}

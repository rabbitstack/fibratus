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

package rules

import (
	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/config"
)

// EnabledSources returns the predicate that tells whether the event source
// the fields of the source are read from is enabled in the configuration.
// The sources that can't be switched off are always enabled.
func EnabledSources(cfg *config.EventSourceConfig) func(fields.Source) bool {
	return func(src fields.Source) bool {
		switch src {
		case fields.SourceRegistry:
			return cfg.EnableRegistryEvents
		case fields.SourceNetwork:
			return cfg.EnableNetEvents
		case fields.SourceFile:
			return cfg.EnableFileIOEvents
		case fields.SourceModule:
			return cfg.EnableModuleEvents
		case fields.SourceMemory:
			return cfg.EnableMemEvents
		case fields.SourceDNS:
			return cfg.EnableDNSEvents
		}
		return true
	}
}

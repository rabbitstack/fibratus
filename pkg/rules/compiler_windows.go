//go:build windows

/*
 * Copyright 2021-present by Nedim Sabic Sabic
 * Copyright 2026 by Mostafa Moradian
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
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/rabbitstack/fibratus/pkg/filter/ql"
)

// referencesApproverEvents checks whether the rule AST contains an event type
// filter for high-volume Windows events that can be approved by the source.
func (c *compiler) referencesApproverEvents(root ql.Node) bool {
	var found bool
	ql.WalkFunc(root, func(n ql.Node) {
		expr, ok := n.(*ql.BinaryExpr)
		if !ok {
			return
		}

		if c.containsEventTypes(expr, event.RegOpenKey, event.OpenThread, event.OpenProcess, event.SetFileInformation) {
			found = true
			return
		}

		if expr.Op == ql.And &&
			c.containsEventTypes(expr, event.CreateFile) &&
			c.containsFieldMatch(expr, fields.FileOperation, ql.Eq, "OPEN") {
			found = true
		}
	})
	return found
}

func updatePlatformCompileResult(rs *config.RulesCompileResult, typ event.Type) {
	if typ == event.MapViewFile || typ == event.UnmapViewFile {
		rs.HasVAMapEvents = true
	}
	if typ == event.OpenProcess || typ == event.OpenThread || typ == event.SetThreadContext ||
		typ == event.CreateSymbolicLinkObject {
		rs.HasAuditAPIEvents = true
	}
}

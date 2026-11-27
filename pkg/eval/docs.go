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

package eval

import (
	"fmt"
	"io"
	"runtime"
	"slices"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
)

// WriteFieldDocs writes the Markdown reference of the filter fields declared on
// the platform the program is built for. The reference is derived from the
// declarations and GetEvaluator, so a field that is added to them is
// documented without any other edit: the description, the type and the
// examples come from the declaration, whether the field is expensive and what
// serves it from the evaluators.
func WriteFieldDocs(w io.Writer) error {
	bySource := make(map[fields.Source][]fields.FieldInfo)
	for _, fi := range fields.Get() {
		src := fi.Field.Source()
		bySource[src] = append(bySource[src], fi)
	}
	sources := make([]fields.Source, 0, len(bySource))
	for src := range bySource {
		sources = append(sources, src)
	}
	slices.SortFunc(sources, func(a, b fields.Source) int { return strings.Compare(string(a), string(b)) })

	var b strings.Builder
	fmt.Fprintf(&b, "# Filter fields (%s)\n\n", runtime.GOOS)
	for _, src := range sources {
		fmt.Fprintf(&b, "## %s\n\n", src)
		for _, fi := range bySource[src] {
			fmt.Fprintf(&b, "### `%s`\n\n", fi.Field)
			fmt.Fprintf(&b, "%s.\n\n", strings.TrimSuffix(fi.Desc, "."))
			fmt.Fprintf(&b, "- Type: `%s`\n", fi.Type)
			if fi.Argument != nil {
				kind := "required"
				if fi.Argument.Optional {
					kind = "optional"
				}
				fmt.Fprintf(&b, "- Argument: %s, `%s`\n", kind, fi.Argument.Pattern)
			}
			if IsExpensive(fi.Field) {
				b.WriteString("- Expensive: reading the field is costly, so put it after the cheap conditions\n")
			}
			if !hasEvaluator(fi.Field) {
				b.WriteString("- Not served: the field always evaluates to the default value\n")
			}
			if fi.Deprecation != nil {
				repl := make([]string, len(fi.Deprecation.Fields))
				for i, f := range fi.Deprecation.Fields {
					repl[i] = "`" + string(f) + "`"
				}
				fmt.Fprintf(&b, "- Deprecated since %s, use %s\n", fi.Deprecation.Since, strings.Join(repl, ", "))
			}
			if len(fi.Examples) > 0 {
				b.WriteString("\nExamples:\n\n```\n")
				for _, ex := range fi.Examples {
					b.WriteString(ex + "\n")
				}
				b.WriteString("```\n")
			}
			b.WriteString("\n")
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

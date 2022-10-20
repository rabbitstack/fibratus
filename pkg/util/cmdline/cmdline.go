/*
 * Copyright 2022-2023 by Nedim Sabic Sabic
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

package cmdline

import (
	"regexp"
	"strings"
)

// splitRegexp declares the regular expression for splitting the string
// by white spaces if the string is not inside a double quote.
var splitRegexp = regexp.MustCompile(`("[^"]+?"\S*|\S+)`)

// Split returns a slice of strings where each element is
// a single argument in the process command line.
func Split(cmdline string) []string { return splitRegexp.FindAllString(cmdline, -1) }

// CleanExe removes the quotes from the executable path and rejoins
// the rest of the command line arguments.
func CleanExe(args []string) string {
	exe := args[0]
	if exe[0] == '"' && exe[len(exe)-1] == '"' {
		return strings.Join(append([]string{exe[1 : len(exe)-1]}, args[1:]...), " ")
	}
	return strings.Join(args, " ")
}

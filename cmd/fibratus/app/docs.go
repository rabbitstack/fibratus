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

package app

import (
	"os/exec"
	"runtime"

	"github.com/spf13/cobra"
)

var docsCmd = &cobra.Command{
	Use:   "docs",
	Short: "Open Fibratus docs in the web browser",
	RunE: func(cmd *cobra.Command, args []string) error {
		if runtime.GOOS == "windows" {
			return exec.Command("rundll32", "url.dll,FileProtocolHandler", "https://www.fibratus.io").Start()
		} else {
			return exec.Command("xdg-open", "https://www.fibratus.io").Start()
		}
	},
}

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
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"runtime"
)

var version string
var commit string
var built string

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version info",
	Run:   versionFn,
}

func versionFn(cmd *cobra.Command, args []string) {
	if version == "" {
		version = "dev"
	}
	_, _ = fmt.Fprintln(
		os.Stdout,
		"\n",
		"Version:", version, "\n",
		"Commit:", commit, "\n",
		"Go compiler:", runtime.Version(), "\n",
		"Built:", built,
	)
}

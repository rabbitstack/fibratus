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
	"errors"
	"github.com/rabbitstack/fibratus/cmd/fibratus/app/capture"
	"github.com/rabbitstack/fibratus/cmd/fibratus/app/config"
	"github.com/rabbitstack/fibratus/cmd/fibratus/app/list"
	"github.com/rabbitstack/fibratus/cmd/fibratus/app/replay"
	"github.com/rabbitstack/fibratus/cmd/fibratus/app/rules"
	"github.com/rabbitstack/fibratus/cmd/fibratus/app/service"
	"github.com/rabbitstack/fibratus/cmd/fibratus/app/stats"
	"github.com/spf13/cobra"
	"runtime"
)

// RootCmd is the entrance to Fibratus CLI
var RootCmd = &cobra.Command{
	Use:   "fibratus",
	Short: "Adversary tradecraft detection, protection, and hunting",
	Long: `
	Fibratus detects, protects, and erradicates advanced adversary tradecraft by scrutinizing
	and asserting a wide spectrum of system events against a behaviour-driven and YARA memory scanner.
	Events can also be shipped to a wide array of output sinks or dumped to capture files for local inspection
	and forensics analysis. You can use filaments to extend Fibratus with your own arsenal of tools and so
	leverage the power of the Python ecosystem.
	`,
	SilenceUsage: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if runtime.GOOS != "windows" {
			return errors.New("fibratus can only be run on Windows operating systems")
		}
		if runtime.GOARCH == "386" {
			return errors.New("fibratus can't be run on 32-bits Windows operating systems")
		}
		return nil
	},
}

func init() {
	RootCmd.AddCommand(capture.Command)
	RootCmd.AddCommand(replay.Command)
	RootCmd.AddCommand(service.Command)
	RootCmd.AddCommand(stats.Command)
	RootCmd.AddCommand(config.Command)
	RootCmd.AddCommand(list.Command)
	RootCmd.AddCommand(rules.Command)
	RootCmd.AddCommand(runCmd)
	RootCmd.AddCommand(docsCmd)
	RootCmd.AddCommand(versionCmd)
}

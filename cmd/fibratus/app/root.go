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
	"github.com/spf13/cobra"
	"runtime"
)

// RootCmd is the entrance to Fibratus CLI
var RootCmd = &cobra.Command{
	Use:   "fibratus",
	Short: "Modern tool for the kernel observability and exploration",
	Long: `
	Fibratus is a tool for exploration and tracing of the Windows kernel.
	It lets you trap system-wide events such as process life-cycle, file system I/O,
	registry modifications or network requests among many other observability signals.
	In a nutshell, Fibratus allows for gaining deep operational visibility into the Windows
	kernel but also processes running on top of it.
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
	RootCmd.AddCommand(runCmd)
	RootCmd.AddCommand(capture.Cmd)
	RootCmd.AddCommand(replayCmd)
	RootCmd.AddCommand(installSvcCmd)
	RootCmd.AddCommand(removeSvcCmd)
	RootCmd.AddCommand(startSvcCmd)
	RootCmd.AddCommand(stopSvcCmd)
	RootCmd.AddCommand(restartSvcCmd)
	RootCmd.AddCommand(statsCmd)
	RootCmd.AddCommand(config.Cmd)
	RootCmd.AddCommand(docsCmd)
	RootCmd.AddCommand(versionCmd)
}

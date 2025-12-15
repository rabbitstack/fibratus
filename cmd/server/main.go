/*
 * Copyright 2019-present by Nedim Sabic Sabic
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

package main

import (
	"os"

	"github.com/rabbitstack/fibratus/internal/server/grpc"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/util/log"
	"github.com/spf13/cobra"
)

var cmd = &cobra.Command{
	Use:     "run",
	Short:   "Bootstrap fibratus server",
	Aliases: []string{"start"},
	RunE:    start,
	Example: `
	# Run 
	fibratus-server run
	`,
}

var (
	cfg = config.NewWithOpts(config.WithRun())
)

func init() {
	cfg.MustViperize(cmd)
}

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(-1)
	}
}

func start(cmd *cobra.Command, args []string) error {
	err := cfg.TryLoadFile(cfg.File())
	notExists := os.IsNotExist(err)
	if err != nil && !notExists {
		return err
	}
	if err := cfg.Init(); err != nil {
		return err
	}
	if err == nil {
		if err := cfg.Validate(); err != nil {
			return err
		}
	}
	if err := log.InitFromConfig(cfg.Log, "fibratus-server.log"); err != nil {
		return err
	}
	srv := grpc.NewServer()
	srv.Run()
	return nil
}

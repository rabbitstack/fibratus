/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/spf13/cobra"
)

var Command = &cobra.Command{
	Use:   "rules",
	Short: "Validate, list, or search detection rules",
}

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate rules for structural and syntactic correctness",
	RunE:  validate,
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List rules",
	RunE:  list,
}

var cfg = config.NewWithOpts(config.WithValidate(), config.WithList())

var (
	summarized bool
)

func init() {
	cfg.MustViperize(Command)

	Command.AddCommand(validateCmd)

	listCmd.PersistentFlags().BoolVarP(&summarized, "summary", "s", false, "Show rules summary by MITRE tactics and techniques")
	Command.AddCommand(listCmd)
}

func validate(cmd *cobra.Command, args []string) error {
	return validateRules()
}

func list(cmd *cobra.Command, args []string) error {
	return listRules(cmd)
}

func emo(s string, args ...any) { fmt.Printf(s, args...) }

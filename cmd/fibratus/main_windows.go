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

package main

import (
	"fmt"
	"github.com/rabbitstack/fibratus/cmd/fibratus/app"
	"golang.org/x/sys/windows/svc"
	"os"
)

func main() {
	// determine if we are running as a Windows Service
	isWinService, err := svc.IsWindowsService()
	if err != nil {
		fmt.Printf("interactive session check failed: %v\n", err)
		os.Exit(-1)
	}
	if isWinService {
		app.RunService()
		return
	}
	if err := app.RootCmd.Execute(); err != nil {
		os.Exit(-1)
	}
}

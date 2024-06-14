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

package service

import (
	"fmt"
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

var statusCommand = &cobra.Command{
	Use:   "status",
	Short: "Check the status of the Fibratus service",
	RunE:  statusService,
}

func statusService(cmd *cobra.Command, args []string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer func() {
		_ = m.Disconnect()
	}()
	s, err := m.OpenService(svcName)
	if err != nil {
		fmt.Printf("Fibratus service is not installed")
		return nil
	}
	defer func() {
		s.Close()
	}()
	status, err := s.Query()
	if err != nil {
		return err
	}
	if status.State != svc.Running {
		fmt.Printf("Fibratus service is not running")
		return nil
	}
	fmt.Printf("Fibratus service is running")
	return nil
}

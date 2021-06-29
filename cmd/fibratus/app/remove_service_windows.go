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
	"fmt"
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

var removeSvcCmd = &cobra.Command{
	Use:   "remove-service",
	Short: "Remove fibratus from the Windows service control manager",
	RunE:  removeService,
}

var errServiceNotInstalled = errors.New("fibratus service is not installed")

func removeService(cmd *cobra.Command, args []string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer func() {
		_ = m.Disconnect()
	}()
	s, err := m.OpenService(svcName)
	if err != nil {
		return errServiceNotInstalled
	}
	defer func() {
		_ = s.Close()
	}()
	err = s.Delete()
	if err != nil {
		return err
	}
	err = eventlog.Remove(svcName)
	if err != nil {
		return fmt.Errorf("couldn't create eventlog remove record: %v", err)
	}
	return nil
}

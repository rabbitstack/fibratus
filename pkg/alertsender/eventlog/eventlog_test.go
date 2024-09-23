/*
 * Copyright 2019-2024 by Nedim Sabic Sabic and Contributors
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

package eventlog

import (
	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestEventlogSender(t *testing.T) {
	s, err := alertsender.Load(alertsender.Config{Type: alertsender.Eventlog, Sender: Config{Enabled: true}})
	require.NoError(t, err)
	require.NotNil(t, s)

	require.NoError(t, s.Send(alertsender.Alert{
		Title: "LSASS memory dumping via legitimate or offensive tools",
		Text: `Detected an attempt by mimikatz.exe process to access and read
	the memory of the Local Security And Authority Subsystem Service
	and subsequently write the C:\\temp\lsass.dmp dump file to the disk device`}))
}

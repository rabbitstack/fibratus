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

package log

import (
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func TestInitFromConfig(t *testing.T) {
	require.Error(t, InitFromConfig(Config{}, "fibratus.log"))
	require.NoError(t, InitFromConfig(Config{Path: "_fixtures", Level: "info", Formatter: "text"}, "fibratus.log"))

	os.Remove("_fixtures\\fibratus.log")

	logrus.Info("fibratus initialized")

	_, err := os.Stat("_fixtures\\fibratus.log")
	require.NoError(t, err)
}
